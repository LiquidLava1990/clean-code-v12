//! Integration tests for [`crate::Kernel`].
//!
//! Each test builds an isolated [`tempfile::TempDir`] repo so the
//! `.gitignore` semantics in `ignore::WalkBuilder` apply faithfully.

use camino::Utf8PathBuf;
use cc_config::Config;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use crate::Kernel;

/// Convenience: build a temp repo, write `files`, and return the root
/// as `Utf8PathBuf`.
fn make_repo(files: &[(&str, &str)]) -> (TempDir, Utf8PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    for (rel, contents) in files {
        let abs = dir.path().join(rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(&abs, contents).expect("write");
    }
    let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("tempdir path is utf8");
    (dir, root)
}

/// 100-LOC Python function — known to trip `R-FN-LEN` (`cc.shape.fn_length`).
fn long_python_function() -> String {
    let mut body = String::from("def long_function(x):\n");
    for i in 0..120 {
        body.push_str(&format!("    y_{i} = x + {i}\n"));
    }
    body.push_str("    return y_0\n");
    body
}

fn default_config(root: &Path) -> Config {
    let utf8 = Utf8PathBuf::from_path_buf(root.to_path_buf()).expect("utf8");
    Config::default_for_repo(&utf8)
}

#[test]
fn long_python_function_fires_at_least_one_finding() {
    let (_dir, root) = make_repo(&[("offender.py", &long_python_function())]);
    let cfg = default_config(root.as_std_path());
    let mut kernel = Kernel::new(cfg).expect("kernel new");
    kernel.with_default_packs().expect("default packs");

    let report = kernel.run(&root).expect("run");
    assert!(
        report.files_scanned >= 1,
        "scanned: {}",
        report.files_scanned
    );
    // We allow for either fn_length or other shape rules to fire — the
    // contract is "at least one finding on a 120-line function".
    assert!(
        !report.findings.is_empty(),
        "expected ≥1 finding on a 120-line python function; got 0"
    );
    assert!(
        report.score.score < 100,
        "expected score < 100 with findings, got {}",
        report.score.score
    );
}

#[test]
fn empty_repo_scores_perfect() {
    let (_dir, root) = make_repo(&[]);
    let cfg = default_config(root.as_std_path());
    let mut kernel = Kernel::new(cfg).expect("kernel new");
    kernel.with_default_packs().expect("default packs");

    let report = kernel.run(&root).expect("run");
    assert_eq!(report.files_scanned, 0);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.score.score, 100);
}

#[test]
fn unsupported_extension_is_skipped() {
    let (_dir, root) = make_repo(&[("note.foo", "this is not source\n")]);
    let cfg = default_config(root.as_std_path());
    let mut kernel = Kernel::new(cfg).expect("kernel new");
    kernel.with_default_packs().expect("default packs");

    let report = kernel.run(&root).expect("run");
    assert_eq!(report.files_scanned, 0);
    assert!(
        report.files_skipped >= 1,
        "expected ≥1 skipped, got {}",
        report.files_skipped
    );
    assert!(report.findings.is_empty());
}

#[test]
fn gitignore_excludes_violator() {
    let (_dir, root) = make_repo(&[
        (".gitignore", "ignored.py\n"),
        ("ignored.py", &long_python_function()),
    ]);
    let cfg = default_config(root.as_std_path());
    let mut kernel = Kernel::new(cfg).expect("kernel new");
    kernel.with_default_packs().expect("default packs");

    let report = kernel.run(&root).expect("run");
    // .gitignore is honored only when the directory is a git repo OR
    // when ignore::WalkBuilder detects the file standalone — which it
    // does via `add_ignore`. Either way, the violating file should not
    // be scanned.
    assert_eq!(
        report.files_scanned, 0,
        "ignored.py should have been gitignored, files_scanned = {}",
        report.files_scanned
    );
    assert!(report.findings.is_empty());
}
