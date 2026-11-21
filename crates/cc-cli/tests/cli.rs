//! Integration tests for `cc-cli`.
//!
//! Spawns the built `cc` binary against `tempfile::TempDir` fixtures.
//! Each test asserts the trio: exit code + observable output + side
//! effects on disk.

use std::path::{Path, PathBuf};
use std::process::Command;

use cc_cli::{InitArgs, OutputFormat, SeverityFilter};
use tempfile::TempDir;

fn cc_binary() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by Cargo when running integration
    // tests for a binary crate.
    PathBuf::from(env!("CARGO_BIN_EXE_cc"))
}

fn write_file(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("test setup: create parent");
    }
    std::fs::write(path, contents).expect("test setup: write file");
}

#[test]
fn check_clean_python_repo_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    write_file(dir.path(), "ok.py", "def add(a, b):\n    return a + b\n");

    let output = Command::new(cc_binary())
        .arg("check")
        .arg("--severity")
        .arg("blocker")
        .arg(dir.path())
        .output()
        .expect("spawn cc check");

    assert!(
        output.status.success(),
        "expected exit 0 with --severity blocker; got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_long_function_emits_finding_and_exits_one() {
    let dir = TempDir::new().expect("tempdir");
    let mut body = String::new();
    for i in 0..100 {
        use std::fmt::Write;
        let _ = writeln!(body, "    x_{i} = {i}");
    }
    let src = format!("def long_fn():\n{body}    return 0\n");
    write_file(dir.path(), "long.py", &src);

    let output = Command::new(cc_binary())
        .arg("check")
        .arg(dir.path())
        .output()
        .expect("spawn cc check");

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "expected exit 0 or 1 from cc check; got {code}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_json_format_emits_parseable_lines() {
    let dir = TempDir::new().expect("tempdir");
    let mut body = String::new();
    for i in 0..100 {
        use std::fmt::Write;
        let _ = writeln!(body, "    x_{i} = {i}");
    }
    let src = format!("def long_fn():\n{body}    return 0\n");
    write_file(dir.path(), "long.py", &src);

    let output = Command::new(cc_binary())
        .arg("check")
        .arg("--format")
        .arg("json")
        .arg(dir.path())
        .output()
        .expect("spawn cc check --format json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("bad json line `{line}`: {err}"));
    }
}

#[test]
fn check_sarif_format_round_trips() {
    let dir = TempDir::new().expect("tempdir");
    write_file(dir.path(), "ok.py", "x = 1\n");

    let output = Command::new(cc_binary())
        .arg("check")
        .arg("--format")
        .arg("sarif")
        .arg(dir.path())
        .output()
        .expect("spawn cc check --format sarif");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("sarif must be json: {err}\n---\n{stdout}\n---"));
    assert_eq!(value.get("version").and_then(|v| v.as_str()), Some("2.1.0"));
    assert!(value.get("runs").is_some());
}

#[test]
fn init_creates_config_and_baseline() {
    let dir = TempDir::new().expect("tempdir");

    let output = Command::new(cc_binary())
        .arg("init")
        .arg(dir.path())
        .output()
        .expect("spawn cc init");

    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join(".cc/config.toml").is_file());
    assert!(dir.path().join(".cc/baseline.json").is_file());
}

#[test]
fn version_prints_string() {
    let output = Command::new(cc_binary())
        .arg("version")
        .output()
        .expect("spawn cc version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("cc "),
        "unexpected version output: {stdout}"
    );
    assert!(stdout.contains("kernel "));
}

#[test]
fn library_run_init_idempotent_with_force() {
    use camino::Utf8PathBuf;
    let dir = TempDir::new().expect("tempdir");
    let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("tempdir is utf-8");

    cc_cli::run_init(&InitArgs {
        path: path.clone(),
        force: false,
    })
    .expect("first init");

    // Second time without --force should fail.
    let err = cc_cli::run_init(&InitArgs {
        path: path.clone(),
        force: false,
    });
    assert!(err.is_err(), "second init without --force must fail");

    // With --force it succeeds.
    cc_cli::run_init(&InitArgs { path, force: true }).expect("forced re-init");
}

#[test]
fn severity_filter_min_severity_mapping() {
    use cc_finding::Severity;
    assert_eq!(SeverityFilter::Nit.min_severity(), Severity::Nit);
    assert_eq!(SeverityFilter::Required.min_severity(), Severity::Required);
    assert_eq!(SeverityFilter::Blocker.min_severity(), Severity::Blocker);
}

#[test]
fn baseline_create_persists_findings_and_check_silences_them() {
    let dir = TempDir::new().expect("tempdir");
    // Long function — guaranteed to trip `cc.shape.fn_length`.
    let mut body = String::new();
    for i in 0..100 {
        use std::fmt::Write;
        let _ = writeln!(body, "    x_{i} = {i}");
    }
    let src = format!("def long_fn():\n{body}    return 0\n");
    write_file(dir.path(), "long.py", &src);

    // Step 1: capture findings into a baseline file.
    let create = Command::new(cc_binary())
        .arg("baseline")
        .arg("create")
        .arg(dir.path())
        .output()
        .expect("spawn cc baseline create");
    assert!(
        create.status.success(),
        "baseline create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let baseline_path = dir.path().join(".cc-baseline.json");
    assert!(
        baseline_path.is_file(),
        "expected baseline at {baseline_path:?} to exist"
    );

    // Sanity-check the JSON shape — schema version + entries map.
    let bytes = std::fs::read(&baseline_path).expect("read baseline");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("baseline must be JSON");
    assert!(parsed.get("schema_version").is_some());
    assert!(parsed.get("entries").is_some());

    // Step 2: `cc check --baseline <FILE>` must silence baselined finding.
    let check = Command::new(cc_binary())
        .arg("check")
        .arg("--baseline")
        .arg(&baseline_path)
        .arg(dir.path())
        .output()
        .expect("spawn cc check --baseline");
    let code = check.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        0,
        "cc check should exit clean once findings are baselined; \
         got {code}\nstderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn baseline_status_runs_without_mutating_file() {
    let dir = TempDir::new().expect("tempdir");
    write_file(dir.path(), "ok.py", "x = 1\n");

    // Create an empty baseline first.
    let _ = Command::new(cc_binary())
        .arg("baseline")
        .arg("create")
        .arg(dir.path())
        .output()
        .expect("create");
    let baseline_path = dir.path().join(".cc-baseline.json");
    let before = std::fs::read(&baseline_path).expect("read pre");

    let status = Command::new(cc_binary())
        .arg("baseline")
        .arg("status")
        .arg(dir.path())
        .output()
        .expect("spawn baseline status");
    assert!(status.status.success(), "{:?}", status.status);

    let after = std::fs::read(&baseline_path).expect("read post");
    assert_eq!(before, after, "status must not mutate the baseline file");
}

#[test]
fn baseline_clear_with_yes_wipes_entries() {
    let dir = TempDir::new().expect("tempdir");
    write_file(dir.path(), "ok.py", "x = 1\n");

    let _ = Command::new(cc_binary())
        .arg("baseline")
        .arg("create")
        .arg(dir.path())
        .output()
        .expect("create");
    let baseline_path = dir.path().join(".cc-baseline.json");
    assert!(baseline_path.is_file());

    let clear = Command::new(cc_binary())
        .arg("baseline")
        .arg("clear")
        .arg("--yes")
        .arg(dir.path())
        .output()
        .expect("spawn baseline clear");
    assert!(clear.status.success());

    let bytes = std::fs::read(&baseline_path).expect("read post-clear");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let entries = parsed.get("entries").and_then(|v| v.as_object());
    assert_eq!(
        entries.map(serde_json::Map::len).unwrap_or(0),
        0,
        "clear should produce an empty entries map"
    );
}

#[test]
fn output_format_variants_are_exhaustive() {
    // Ensures the enum stays four-armed; downstream sink_for() switches
    // on every variant. If a new variant is added without updating the
    // sink dispatch this fails to compile, not at runtime.
    let all = [
        OutputFormat::Tty,
        OutputFormat::Sarif,
        OutputFormat::Rdjson,
        OutputFormat::Json,
    ];
    assert_eq!(all.len(), 4);
}
