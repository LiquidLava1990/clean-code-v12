//! Integration tests for the `cc harness` subcommand.
//!
//! Ten contract tests that lock in the test-first / pre-refactor safety
//! net behaviour of `cc harness init|verify|regenerate` across all
//! seven layers:
//!
//! 1. `init` scaffolds the seven layers (helpers + tests + snapshots).
//! 2. `init` is idempotent — second run prints the canonical message.
//! 3. `verify` returns 0 on a clean repo immediately after `init`.
//! 4. `verify` returns non-zero after a deliberate signature drift.
//! 5. `regenerate` rebases the snapshots so a follow-up `verify` is green.
//! 6. `init` skips with a clear error (not a panic) when `python` is
//!    absent on `PATH`.
//! 7. Layer 4 — new `import` triggers dependency drift.
//! 8. Layer 5 — new `# TODO` comment triggers slop-marker drift.
//! 9. Layer 6 — new public top-level def triggers public-API drift.
//! 10. Layer 7 — new `# noqa: <rule>` triggers suppression drift.
//!
//! Each test seeds a `tempfile::TempDir` with the smallest possible
//! Python project (one module, no externals) and exec's the built `cc`
//! binary. Tests are pure black-box — they only assert on filesystem
//! state, exit codes, and human-readable stderr.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Resolve the path to the `cc` binary. Cargo populates
/// `CARGO_BIN_EXE_<name>` for integration tests of binary crates.
fn cc_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cc"))
}

/// Write `contents` to `<dir>/<rel>`, creating parent dirs as needed.
fn write_file(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("test setup: create parent");
    }
    std::fs::write(path, contents).expect("test setup: write file");
}

/// Seed a single trivial Python module + an empty `pyproject.toml`.
fn seed_python_project(dir: &Path) {
    write_file(
        dir,
        "src/sample.py",
        "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n",
    );
    write_file(
        dir,
        "pyproject.toml",
        "[project]\nname = \"sample\"\nversion = \"0.0.0\"\n",
    );
}

/// True when `python` (or `python3`) is on PATH AND can import pytest.
/// `cc harness` shells out to the interpreter for both `init` (snapshot
/// regen) and `verify` (pytest run); without pytest the harness cannot
/// complete a real run, only the python-missing error path.
fn python_with_pytest_available() -> bool {
    for bin in ["python", "python3"] {
        let probe = Command::new(bin).args(["-c", "import pytest"]).output();
        if let Ok(out) = probe {
            if out.status.success() {
                return true;
            }
        }
    }
    false
}

/// True when ANY python interpreter answers `--version` on this PATH.
fn python_available() -> bool {
    for bin in ["python", "python3"] {
        let probe = Command::new(bin).arg("--version").output();
        if let Ok(out) = probe {
            if out.status.success() {
                return true;
            }
        }
    }
    false
}

/// Harness helper modules `cc harness init` must scaffold (one per layer
/// plus discovery).
const HARNESS_HELPERS: &[&str] = &[
    "_discovery.py",
    "_import_helper.py",
    "_signature_capture.py",
    "_exception_shape.py",
    "_dependency_capture.py",
    "_marker_capture.py",
    "_public_api_capture.py",
    "_suppression_capture.py",
];

/// Harness test + support files `cc harness init` must scaffold.
const HARNESS_TEST_FILES: &[&str] = &[
    "test_imports.py",
    "test_signatures.py",
    "test_exception_handlers.py",
    "test_dependencies.py",
    "test_slop_markers.py",
    "test_public_api.py",
    "test_suppressions.py",
    "regenerate_signatures.py",
    "conftest.py",
    "__init__.py",
    "README.md",
];

/// Baseline snapshots `cc harness init` must write.
const HARNESS_SNAPSHOTS: &[&str] = &[
    "signatures.json",
    "exception_shapes.json",
    "dependencies.json",
    "slop_markers.json",
    "public_api.json",
    "suppressions.json",
];

/// Assert every `names` entry exists under `root` and is non-empty.
fn assert_non_empty_files(root: &Path, names: &[&str], kind: &str) {
    for name in names {
        let path = root.join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|err| {
            panic!("missing {kind} {path:?}: {err}");
        });
        assert!(!bytes.is_empty(), "{kind} {path:?} is empty");
    }
}

/// Assert the snapshot directory holds every baseline snapshot.
fn assert_snapshots_present(harness_root: &Path) {
    let snapshots = harness_root.join("snapshots");
    assert!(snapshots.is_dir(), "snapshots dir missing at {snapshots:?}");
    for snap in HARNESS_SNAPSHOTS {
        assert!(
            snapshots.join(snap).is_file(),
            "{snap} missing under {snapshots:?}",
        );
    }
}

#[test]
fn test_harness_init_scaffolds_seven_layers() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let output = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn cc harness init");

    assert!(
        output.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let harness_root = dir.path().join("tests").join("cc_harness");
    assert_non_empty_files(&harness_root, HARNESS_HELPERS, "helper");
    assert_non_empty_files(&harness_root, HARNESS_TEST_FILES, "harness file");
    assert_snapshots_present(&harness_root);

    let pyproject =
        std::fs::read_to_string(dir.path().join("pyproject.toml")).expect("read pyproject");
    assert!(
        pyproject.contains("tests/cc_harness"),
        "pyproject.toml should record the cc_harness testpath; got:\n{pyproject}"
    );
}

#[test]
fn test_harness_init_idempotent() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let first = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn cc harness init #1");
    assert!(first.status.success(), "first init must succeed");

    // Tag a sentinel byte in one helper so we can detect destructive overwrite.
    let helper = dir.path().join("tests/cc_harness/_discovery.py");
    let original = std::fs::read(&helper).expect("read helper");

    let second = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn cc harness init #2");
    assert!(
        second.status.success(),
        "second init must exit 0 (no-op): {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already initialized") || stderr.contains("already initialised"),
        "second init must announce already-initialised; got: {stderr}"
    );

    let after = std::fs::read(&helper).expect("re-read helper");
    assert_eq!(original, after, "second init must not overwrite helpers");
}

#[test]
fn test_harness_verify_returns_zero_on_clean_repo() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let init = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn init");
    assert!(init.status.success(), "init must pass first");

    let verify = Command::new(cc_binary())
        .arg("harness")
        .arg("verify")
        .arg(dir.path())
        .output()
        .expect("spawn verify");
    let code = verify.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        0,
        "verify on clean tree should be green; got {code}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

#[test]
fn test_harness_verify_returns_nonzero_on_signature_drift() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let init = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("init");
    assert!(init.status.success(), "init must succeed before drift test");

    // Mutate the public surface — add a parameter to `add`.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b, c=0):\n    return a + b + c\n\n\ndef sub(a, b):\n    return a - b\n",
    );

    let verify = Command::new(cc_binary())
        .arg("harness")
        .arg("verify")
        .arg(dir.path())
        .output()
        .expect("spawn verify");
    let code = verify.status.code().unwrap_or(-1);
    assert_ne!(
        code,
        0,
        "verify after signature drift must be non-zero; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

#[test]
fn test_harness_regenerate_updates_snapshots_and_passes_verify() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let _ = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("init");

    // Deliberate API change — the kind operators ratify with `regenerate`.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b, c=0):\n    return a + b + c\n\n\ndef sub(a, b):\n    return a - b\n",
    );

    let regen = Command::new(cc_binary())
        .arg("harness")
        .arg("regenerate")
        .arg(dir.path())
        .output()
        .expect("spawn regenerate");
    assert!(
        regen.status.success(),
        "regenerate must succeed: {}",
        String::from_utf8_lossy(&regen.stderr)
    );

    let verify = Command::new(cc_binary())
        .arg("harness")
        .arg("verify")
        .arg(dir.path())
        .output()
        .expect("spawn verify post-regen");
    assert_eq!(
        verify.status.code(),
        Some(0),
        "verify after regenerate must be green; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
    );
}

/// Run `cc harness init` then assert it succeeded — small helper for
/// the layer-specific drift tests so each one stays focused on its
/// one mutation.
fn init_or_panic(dir: &Path) {
    let init = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir)
        .output()
        .expect("spawn cc harness init");
    assert!(
        init.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr),
    );
}

/// Run `cc harness verify <dir>` and return (exit_code, stdout, stderr).
fn verify_capture(dir: &Path) -> (i32, String, String) {
    let v = Command::new(cc_binary())
        .arg("harness")
        .arg("verify")
        .arg(dir)
        .output()
        .expect("spawn cc harness verify");
    (
        v.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&v.stdout).into_owned(),
        String::from_utf8_lossy(&v.stderr).into_owned(),
    )
}

#[test]
fn test_layer_dependencies_catches_new_import() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());
    init_or_panic(dir.path());

    // Add a new top-level import that wasn't in the snapshot.
    write_file(
        dir.path(),
        "src/sample.py",
        "import asyncio\n\n\ndef add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n",
    );

    let (code, stdout, stderr) = verify_capture(dir.path());
    assert_ne!(code, 0, "new import must fail verify");
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("dependency drift") || combined.contains("DEPS DRIFT"),
        "expected dependency drift message; got:\n{combined}"
    );
}

#[test]
fn test_layer_slop_markers_catches_new_todo() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    // Seed with an existing TODO so the snapshot has a baseline.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b):\n    # TODO: validate inputs\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n",
    );
    write_file(
        dir.path(),
        "pyproject.toml",
        "[project]\nname = \"sample\"\nversion = \"0.0.0\"\n",
    );
    init_or_panic(dir.path());

    // Add a NEW TODO -- existing one stays, count goes 1 -> 2.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b):\n    # TODO: validate inputs\n    return a + b\n\n\ndef sub(a, b):\n    # TODO: handle overflow\n    return a - b\n",
    );

    let (code, stdout, stderr) = verify_capture(dir.path());
    assert_ne!(code, 0, "new TODO must fail verify");
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("new slop markers") || combined.contains("new TODO"),
        "expected slop-marker drift message; got:\n{combined}"
    );
}

#[test]
fn test_layer_public_api_catches_added_export() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());
    init_or_panic(dir.path());

    // Add a brand-new public top-level def — implicit __all__ should grow.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n\n\ndef multiply(a, b):\n    return a * b\n",
    );

    let (code, stdout, stderr) = verify_capture(dir.path());
    assert_ne!(code, 0, "new public def must fail verify");
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("public-API drift") || combined.contains("PUBLIC API DRIFT"),
        "expected public-API drift message; got:\n{combined}"
    );
}

#[test]
fn test_layer_suppressions_catches_new_noqa() {
    if !python_with_pytest_available() {
        eprintln!("SKIP: python+pytest not on PATH");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());
    init_or_panic(dir.path());

    // Add a NEW noqa suppression to a previously-clean file.
    write_file(
        dir.path(),
        "src/sample.py",
        "def add(a, b):  # noqa: E501\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n",
    );

    let (code, stdout, stderr) = verify_capture(dir.path());
    assert_ne!(code, 0, "new noqa must fail verify");
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("suppression") || combined.contains("noqa"),
        "expected suppression drift message; got:\n{combined}"
    );
}

#[test]
fn test_harness_init_skips_if_python_unavailable() {
    if python_available() {
        eprintln!("SKIP: python IS on PATH; cannot exercise the missing-python branch");
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    seed_python_project(dir.path());

    let output = Command::new(cc_binary())
        .arg("harness")
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn cc harness init");

    let code = output.status.code().unwrap_or(-1);
    assert_ne!(code, 0, "init without python must not exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("python"),
        "missing-python error must mention python; got: {stderr}"
    );
}
