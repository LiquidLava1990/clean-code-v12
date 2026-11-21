//! Integration tests for `cc-incremental`.
//!
//! These cover the six acceptance criteria from the W1.T6 spec:
//!
//! 1. `file_input_hash_change_invalidates`
//! 2. `parse_caches_across_calls`
//! 3. `cpg_invalidates_on_file_change`
//! 4. `health_score_propagates`
//! 5. `watcher_detects_file_modify`
//! 6. `remove_file_clears_queries`

use std::sync::Arc;
use std::time::Duration;

use camino::Utf8Path;
use cc_incremental::{CcDatabase, ContentHash, WatcherHandle};

#[test]
fn file_input_hash_change_invalidates() {
    let mut db = CcDatabase::new();
    let f = db.add_file("a.rs", "fn a() {}", "rust");
    let initial_hash = f.content_hash(&db);

    // Same content -> no change.
    let changed = db.update_file(f, "fn a() {}");
    assert!(!changed, "same content must not invalidate");
    assert_eq!(initial_hash, f.content_hash(&db));

    // Different content -> change.
    let changed = db.update_file(f, "fn a() { let x = 1; }");
    assert!(changed, "different content must invalidate");
    assert_ne!(initial_hash, f.content_hash(&db));
}

#[test]
fn content_hash_is_deterministic() {
    let h1 = ContentHash::of(b"hello world");
    let h2 = ContentHash::of(b"hello world");
    let h3 = ContentHash::of(b"hello world!");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

#[test]
fn parse_caches_across_calls() {
    let mut db = CcDatabase::new();
    let f = db.add_file("b.rs", "fn b() {}", "rust");

    let t1 = db.parsed_tree(f);
    let t2 = db.parsed_tree(f);
    // Cached -> same Arc identity.
    assert!(
        Arc::ptr_eq(&t1.0, &t2.0),
        "parsed_tree must return the cached Arc on a no-op call"
    );
}

#[test]
fn cpg_invalidates_on_file_change() {
    let mut db = CcDatabase::new();
    let f = db.add_file("c.rs", "fn c() {}", "rust");

    let cpg1 = db.cpg_root(f);
    db.update_file(f, "fn c() { let y = 2; }");
    let cpg2 = db.cpg_root(f);
    assert!(
        !Arc::ptr_eq(&cpg1.0, &cpg2.0),
        "cpg_root must recompute after content change"
    );
}

#[test]
fn cpg_caches_when_other_files_change() {
    let mut db = CcDatabase::new();
    let f1 = db.add_file("d1.rs", "fn d1() {}", "rust");
    let f2 = db.add_file("d2.rs", "fn d2() {}", "rust");

    let cpg1_a = db.cpg_root(f1);
    db.update_file(f2, "fn d2() { let z = 3; }");
    let cpg1_b = db.cpg_root(f1);
    assert!(
        Arc::ptr_eq(&cpg1_a.0, &cpg1_b.0),
        "f1 cpg_root must remain cached when only f2 changes"
    );
}

#[test]
fn health_score_propagates() {
    let mut db = CcDatabase::new();
    let f1 = db.add_file("h1.rs", "fn h1() {}", "rust");
    let f2 = db.add_file("h2.rs", "fn h2() {}", "rust");
    let repo = db.build_repo_input("/repo");

    let s1 = db.repo_health_score(repo);
    let per_f2_a = db.health_score_for_file(f2);

    // Mutate f1 only — f2's per-file score must remain stable.
    db.update_file(f1, "fn h1() { let q = 1; }");
    let per_f2_b = db.health_score_for_file(f2);
    assert!((per_f2_a - per_f2_b).abs() < f64::EPSILON);

    // Repo score recomputes; with no rules registered it stays at 1.0.
    let s2 = db.repo_health_score(repo);
    assert!((s1 - s2).abs() < f64::EPSILON);
}

#[test]
fn remove_file_clears_path_index() {
    let mut db = CcDatabase::new();
    let f = db.add_file("r.rs", "fn r() {}", "rust");
    assert!(db.lookup_path(Utf8Path::new("r.rs")).is_some());
    db.remove_file(f);
    assert!(
        db.lookup_path(Utf8Path::new("r.rs")).is_none(),
        "remove_file must drop the path -> FileInput mapping"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watcher_detects_file_modify() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root =
        camino::Utf8PathBuf::from_path_buf(tmp.path().to_owned()).expect("tempdir path is utf-8");
    let target = root.join("watched.rs");
    // Async-native writes: the runtime stays cooperative, and the
    // sync-in-async lint stays quiet. `tokio::fs::write` returns once
    // the kernel has buffered the bytes — semantically identical to
    // `std::fs::write` for the watcher's purposes.
    tokio::fs::write(target.as_std_path(), "fn v1() {}")
        .await
        .expect("seed initial file");

    let mut handle = WatcherHandle::start(&root).expect("start watcher");

    // Modify the file then assert the watcher reports the new hash.
    // We drive synchronisation off the actual signal — the event whose
    // hash matches the post-write content — rather than a wall-clock
    // sleep. Any in-flight events for the *initial* write are
    // intentionally ignored: we keep recv-ing inside the deadline until
    // the matching hash arrives. notify can deliver Windows
    // ReadDirectoryChangesW events in 1-2s, so the budget is generous.
    tokio::fs::write(target.as_std_path(), "fn v2() { let x = 1; }")
        .await
        .expect("write modified file");
    let expected = ContentHash::of(b"fn v2() { let x = 1; }");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let event = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(remaining, handle.events.recv())
            .await
            .expect("watcher must deliver matching event within 5s")
            .expect("channel closed");
        if next.new_hash == expected {
            break next;
        }
        // Stale event from the initial create; keep polling.
    };
    assert_eq!(event.new_hash, expected);
}
