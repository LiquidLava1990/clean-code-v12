//! Behavioural tests for [`BaselineRepo`].

mod common;

use camino::Utf8PathBuf;
use cc_baseline::{apply, BaselineRepo};
use chrono::{Duration, Utc};
use common::finding_with_node;
use tempfile::tempdir;

fn tmp_path(dir: &tempfile::TempDir, name: &str) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(dir.path().join(name)).expect("utf8 tempdir")
}

#[test]
fn open_missing_path_returns_empty_baseline() {
    let dir = tempdir().expect("tempdir");
    let path = tmp_path(&dir, "does_not_exist.json");
    let repo = BaselineRepo::open(&path).expect("missing-file open is not an error");
    assert!(repo.is_empty());
    assert_eq!(repo.len(), 0);
}

#[test]
fn accept_dedupes() {
    let f = finding_with_node("fn a() {}", "n:a");
    let mut repo = BaselineRepo::empty();

    let inserted_first = repo.accept(&f, Some("legacy".into()), Some("alice".into()));
    let inserted_second = repo.accept(&f, Some("ignored".into()), Some("bob".into()));

    assert!(inserted_first, "first accept inserts");
    assert!(!inserted_second, "second accept dedupes");
    assert_eq!(repo.len(), 1);
    let entry = repo.get(&f.suppress_key).expect("entry present");
    assert_eq!(entry.seen_count, 2);
    // First reason wins on dedup; touch does not overwrite metadata.
    assert_eq!(entry.reason.as_deref(), Some("legacy"));
    assert_eq!(entry.accepted_by.as_deref(), Some("alice"));
}

#[test]
fn apply_partitions_correctly() {
    let f1 = finding_with_node("fn a() {}", "n:a");
    let f2 = finding_with_node("fn b() {}", "n:b");
    let f3 = finding_with_node("fn c() {}", "n:c");

    let mut repo = BaselineRepo::empty();
    repo.accept(&f1, None, None);
    repo.accept(&f2, None, None);

    let outcome = apply(&mut repo, &[f1.clone(), f2.clone(), f3.clone()]);

    assert_eq!(outcome.new.len(), 1);
    assert_eq!(outcome.new[0].suppress_key, f3.suppress_key);
    assert_eq!(outcome.persisted.len(), 2);
    assert!(outcome.escaped.is_empty());
}

#[test]
fn apply_touches_persisted() {
    let f = finding_with_node("fn a() {}", "n:a");
    let mut repo = BaselineRepo::empty();
    repo.accept(&f, None, None); // seen_count = 1

    let outcome = apply(&mut repo, &[f.clone()]);
    assert_eq!(outcome.persisted.len(), 1);
    let entry = repo.get(&f.suppress_key).expect("present");
    assert_eq!(entry.seen_count, 2, "apply must touch persisted entries");
}

#[test]
fn apply_reports_escaped() {
    let f_in_baseline = finding_with_node("fn a() {}", "n:a");
    let f_seen_now = finding_with_node("fn b() {}", "n:b");

    let mut repo = BaselineRepo::empty();
    repo.accept(&f_in_baseline, None, None);

    let outcome = apply(&mut repo, &[f_seen_now]);
    assert_eq!(outcome.escaped.len(), 1);
    assert_eq!(outcome.escaped[0], f_in_baseline.suppress_key);
}

#[test]
fn prune_unseen_removes_old() {
    let f = finding_with_node("fn a() {}", "n:a");
    let mut repo = BaselineRepo::empty();
    repo.accept(&f, None, None);

    // Backdate the entry's last_seen_at so prune sees it as stale. We
    // do this by serialising, mutating, deserialising — simulating a
    // baseline that's been on disk for weeks.
    let mut json: serde_json::Value = serde_json::to_value(repo.baseline()).unwrap();
    let entries = json["entries"].as_object_mut().unwrap();
    for (_, e) in entries.iter_mut() {
        e["last_seen_at"] = serde_json::Value::String("2000-01-01T00:00:00Z".into());
    }
    let dir = tempdir().unwrap();
    let path = tmp_path(&dir, "stale.json");
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    let mut reopened = BaselineRepo::open(&path).expect("reopen");

    let cutoff = Utc::now() - Duration::days(1);
    let removed = reopened.prune_unseen_since(cutoff);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0], f.suppress_key);
    assert!(!reopened.contains(&f.suppress_key));
}

#[test]
fn save_load_round_trip() {
    let dir = tempdir().expect("tempdir");
    let path = tmp_path(&dir, "baseline.json");

    let f = finding_with_node("fn a() {}", "n:a");
    let mut repo = BaselineRepo::empty();
    repo.accept(&f, Some("legacy".into()), Some("alice".into()));
    repo.save(&path).expect("save");

    let loaded = BaselineRepo::open(&path).expect("load");
    assert_eq!(loaded.baseline(), repo.baseline());
}

#[test]
fn serde_round_trip_preserves_suppress_key() {
    let f = finding_with_node("fn a() {}", "n:a");
    let mut repo = BaselineRepo::empty();
    repo.accept(&f, None, None);

    let bytes = serde_json::to_vec(repo.baseline()).expect("encode");
    let decoded: cc_baseline::Baseline = serde_json::from_slice(&bytes).expect("decode");
    assert!(decoded.entries.contains_key(&f.suppress_key));
}

#[test]
fn create_bulk_accepts_all_findings() {
    let f1 = finding_with_node("fn a() {}", "n:a");
    let f2 = finding_with_node("fn b() {}", "n:b");
    let repo = BaselineRepo::create(&[f1.clone(), f2], Some("deadbeef"), Some("carol"));
    assert_eq!(repo.len(), 2);
    assert_eq!(repo.baseline().git_ref.as_deref(), Some("deadbeef"));
    let entry = repo.get(&f1.suppress_key).expect("present");
    assert_eq!(entry.accepted_by.as_deref(), Some("carol"));
}

#[test]
fn merge_keeps_most_recent_metadata() {
    let f = finding_with_node("fn a() {}", "n:a");
    let mut a = BaselineRepo::empty();
    let mut b = BaselineRepo::empty();
    a.accept(&f, Some("from-a".into()), Some("alice".into()));
    b.accept(&f, Some("from-b".into()), Some("bob".into()));
    // b accepted second → b.last_seen_at >= a.last_seen_at.
    let merged = a.merge(b);
    let entry = merged.get(&f.suppress_key).expect("present");
    assert_eq!(entry.seen_count, 2, "merge sums seen_count");
    assert_eq!(
        entry.reason.as_deref(),
        Some("from-b"),
        "more-recently-seen wins"
    );
}
