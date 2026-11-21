//! `ccv12 harness` — scaffold + verify the 7-layer pre-refactor safety net.
//!
//! The harness is the test-first / pre-refactor gate that ships with V12.
//! Three subcommands:
//!
//! - `ccv12 harness init <PATH>` — write the helper modules, test modules,
//!   and a baseline snapshot under `<PATH>/tests/cc_harness/`. Idempotent;
//!   re-running prints "already initialised" and exits clean.
//! - `ccv12 harness verify <PATH>` — invoke `python -m pytest` against the
//!   harness package and pass through the exit code.
//! - `ccv12 harness regenerate <PATH>` — re-run `regenerate_signatures.py`
//!   to ratify deliberate API changes, then prompt the operator to commit
//!   the new snapshots.
//!
//! Every template ships embedded in the binary via [`include_str!`], so
//! the harness drops in cleanly even when the cc-cli source tree is not
//! on the operator's machine.
//!
//! # Forever rules atop
//! - Functions ≤50 LOC, nesting ≤3, no `unwrap()` outside tests.
//! - Atomic file writes via `<file>.cc-tmp` + rename.
//! - R-ERR-ACTION dogfood — every error variant carries a fix hint.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use camino::{Utf8Path, Utf8PathBuf};

use crate::args::HarnessArgs;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::runner::canonicalise_root;

/// Suffix of the temp sibling file used by [`atomic_write`].
const TMP_SUFFIX: &str = ".cc-tmp";

/// Relative directory the harness lives in (under `<repo>/tests/`).
const HARNESS_REL_DIR: &str = "tests/cc_harness";

/// One template file, identified by destination basename.
#[derive(Debug, Clone, Copy)]
struct Template {
    /// File name written under `tests/cc_harness/`.
    name: &'static str,
    /// File body, embedded at compile time.
    body: &'static str,
}

/// All scaffolded files. Order is informational only — writes are
/// idempotent and the order doesn't affect correctness.
const TEMPLATES: &[Template] = &[
    Template {
        name: "__init__.py",
        body: include_str!("../harness_templates/__init__.py"),
    },
    Template {
        name: "_discovery.py",
        body: include_str!("../harness_templates/_discovery.py"),
    },
    Template {
        name: "_import_helper.py",
        body: include_str!("../harness_templates/_import_helper.py"),
    },
    Template {
        name: "_signature_capture.py",
        body: include_str!("../harness_templates/_signature_capture.py"),
    },
    Template {
        name: "_exception_shape.py",
        body: include_str!("../harness_templates/_exception_shape.py"),
    },
    Template {
        name: "_dependency_capture.py",
        body: include_str!("../harness_templates/_dependency_capture.py"),
    },
    Template {
        name: "_marker_capture.py",
        body: include_str!("../harness_templates/_marker_capture.py"),
    },
    Template {
        name: "_public_api_capture.py",
        body: include_str!("../harness_templates/_public_api_capture.py"),
    },
    Template {
        name: "_suppression_capture.py",
        body: include_str!("../harness_templates/_suppression_capture.py"),
    },
    Template {
        name: "conftest.py",
        body: include_str!("../harness_templates/conftest.py"),
    },
    Template {
        name: "test_imports.py",
        body: include_str!("../harness_templates/test_imports.py"),
    },
    Template {
        name: "test_signatures.py",
        body: include_str!("../harness_templates/test_signatures.py"),
    },
    Template {
        name: "test_exception_handlers.py",
        body: include_str!("../harness_templates/test_exception_handlers.py"),
    },
    Template {
        name: "test_dependencies.py",
        body: include_str!("../harness_templates/test_dependencies.py"),
    },
    Template {
        name: "test_slop_markers.py",
        body: include_str!("../harness_templates/test_slop_markers.py"),
    },
    Template {
        name: "test_public_api.py",
        body: include_str!("../harness_templates/test_public_api.py"),
    },
    Template {
        name: "test_suppressions.py",
        body: include_str!("../harness_templates/test_suppressions.py"),
    },
    Template {
        name: "regenerate_signatures.py",
        body: include_str!("../harness_templates/regenerate_signatures.py"),
    },
    Template {
        name: "README.md",
        body: include_str!("../harness_templates/README.md"),
    },
];

/// Resolved paths used by every subcommand.
pub(crate) struct HarnessPaths {
    root: Utf8PathBuf,
    harness_dir: Utf8PathBuf,
    snapshots_dir: Utf8PathBuf,
    regenerate_script: Utf8PathBuf,
    pyproject: Utf8PathBuf,
}

impl HarnessPaths {
    fn resolve(root: Utf8PathBuf) -> Self {
        let harness_dir = root.join(HARNESS_REL_DIR);
        let snapshots_dir = harness_dir.join("snapshots");
        let regenerate_script = harness_dir.join("regenerate_signatures.py");
        let pyproject = root.join("pyproject.toml");
        Self {
            root,
            harness_dir,
            snapshots_dir,
            regenerate_script,
            pyproject,
        }
    }
}

/// Top-level dispatcher for `ccv12 harness <SUB>`.
///
/// # Errors
/// Surfaces every [`CliError`] variant — invalid root, I/O failure,
/// missing python, or a pytest non-zero from `verify`.
pub fn run_harness(args: &HarnessArgs) -> Result<ExitCode> {
    match &args.cmd {
        crate::args::HarnessCmd::Init(a) => run_harness_init(&a.path),
        crate::args::HarnessCmd::Verify(a) => run_harness_verify(&a.path),
        crate::args::HarnessCmd::Regenerate(a) => run_harness_regenerate(&a.path),
    }
}

/// Implements `ccv12 harness init <PATH>`.
///
/// 1. Validate `<PATH>` exists.
/// 2. If `tests/cc_harness/` already exists, print and exit clean.
/// 3. Mkdir the harness + snapshots dirs.
/// 4. Write every template atomically.
/// 5. Ensure `pyproject.toml` lists the harness in `testpaths`.
/// 6. Spawn `python regenerate_signatures.py` to capture the baseline.
///
/// # Errors
/// Returns [`CliError::Io`] on any filesystem failure, or
/// [`CliError::Harness`] when the regenerate script fails.
pub fn run_harness_init(path: &Utf8Path) -> Result<ExitCode> {
    let root = canonicalise_root(path)?;
    let paths = HarnessPaths::resolve(root);

    if paths.harness_dir.exists() {
        let _ = writeln!(
            io::stderr(),
            "harness already initialized at {} — run `ccv12 harness verify {}` instead",
            paths.harness_dir,
            paths.root
        );
        return Ok(ExitCode::Clean);
    }

    ensure_dir(&paths.harness_dir)?;
    ensure_dir(&paths.snapshots_dir)?;
    write_all_templates(&paths.harness_dir)?;
    update_pyproject(&paths.pyproject)?;

    let captured = run_regenerate(&paths)?;
    print_init_summary(&paths, captured);
    Ok(ExitCode::Clean)
}

/// Implements `ccv12 harness verify <PATH>` — pytest pass-through.
///
/// # Errors
/// Returns [`CliError::Harness`] when python is unavailable or pytest
/// cannot start. A pytest non-zero is mapped to [`ExitCode::Findings`]
/// so CI gates can fail the build without a stack trace.
pub fn run_harness_verify(path: &Utf8Path) -> Result<ExitCode> {
    let root = canonicalise_root(path)?;
    let paths = HarnessPaths::resolve(root);
    if !paths.harness_dir.exists() {
        return Err(harness_error(
            format!("harness not initialised at {}", paths.harness_dir),
            "run `ccv12 harness init <repo>` to scaffold the harness first",
        ));
    }
    let mut cmd = python_command()?;
    cmd.current_dir(paths.root.as_std_path())
        .args(["-m", "pytest", HARNESS_REL_DIR])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null());
    let status = cmd.status().map_err(spawn_failure)?;
    Ok(if status.success() {
        ExitCode::Clean
    } else {
        ExitCode::Findings
    })
}

/// Implements `ccv12 harness regenerate <PATH>`.
///
/// # Errors
/// Returns [`CliError::Harness`] when python is unavailable or the
/// regenerate script exits non-zero.
pub fn run_harness_regenerate(path: &Utf8Path) -> Result<ExitCode> {
    let root = canonicalise_root(path)?;
    let paths = HarnessPaths::resolve(root);
    if !paths.regenerate_script.exists() {
        return Err(harness_error(
            format!("regenerate script missing at {}", paths.regenerate_script),
            "run `ccv12 harness init <repo>` first to scaffold the harness",
        ));
    }
    let _ = run_regenerate(&paths)?;
    let _ = writeln!(
        io::stderr(),
        "snapshots regenerated under {} — review the diff and commit",
        paths.snapshots_dir
    );
    Ok(ExitCode::Clean)
}

// ---------------------------------------------------------------------
// Helpers — filesystem + templates
// ---------------------------------------------------------------------

fn ensure_dir(dir: &Utf8Path) -> Result<()> {
    std::fs::create_dir_all(dir.as_std_path()).map_err(|source| CliError::Io {
        context: "harness_create_dir",
        source,
    })
}

fn write_all_templates(dst_dir: &Utf8Path) -> Result<()> {
    for template in TEMPLATES {
        let dest = dst_dir.join(template.name);
        atomic_write(&dest, template.body.as_bytes())?;
    }
    Ok(())
}

/// Atomic write: write `<path>.cc-tmp` then rename onto `<path>`.
fn atomic_write(path: &Utf8Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_sibling(path);
    write_then_sync(&tmp, bytes)?;
    rename_or_fallback(&tmp, path.as_std_path())
}

fn tmp_sibling(path: &Utf8Path) -> PathBuf {
    let mut tmp = PathBuf::from(path.as_std_path());
    let mut name = tmp
        .file_name()
        .unwrap_or_else(|| OsStr::new("template"))
        .to_os_string();
    name.push(TMP_SUFFIX);
    tmp.set_file_name(name);
    tmp
}

fn write_then_sync(tmp: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::File::create(tmp).map_err(|source| CliError::Io {
        context: "harness_template_create",
        source,
    })?;
    file.write_all(bytes).map_err(|source| CliError::Io {
        context: "harness_template_write",
        source,
    })?;
    file.sync_all().map_err(|source| CliError::Io {
        context: "harness_template_fsync",
        source,
    })
}

fn rename_or_fallback(tmp: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    if std::fs::rename(tmp, dst).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(dst);
    std::fs::rename(tmp, dst).map_err(|source| {
        let _ = std::fs::remove_file(tmp);
        CliError::Io {
            context: "harness_template_rename",
            source,
        }
    })
}

// ---------------------------------------------------------------------
// pyproject.toml stitching
// ---------------------------------------------------------------------

const TESTPATHS_LINE: &str = "testpaths = [\"tests\", \"tests/cc_harness\"]";
const PYTEST_HEADER: &str = "[tool.pytest.ini_options]";
const PYPROJECT_DEFAULT: &str = "[project]\nname = \"cc-harness-host\"\nversion = \"0.0.0\"\n";

fn update_pyproject(path: &Utf8Path) -> Result<()> {
    let existing = read_or_default_pyproject(path)?;
    if existing.contains("tests/cc_harness") {
        return Ok(());
    }
    let updated = inject_testpaths(&existing);
    atomic_write(path, updated.as_bytes())
}

fn read_or_default_pyproject(path: &Utf8Path) -> Result<String> {
    if !path.exists() {
        return Ok(PYPROJECT_DEFAULT.to_owned());
    }
    std::fs::read_to_string(path.as_std_path()).map_err(|source| CliError::Io {
        context: "harness_pyproject_read",
        source,
    })
}

/// Append a `[tool.pytest.ini_options]` section listing the harness as a
/// test path. If the section already exists without the entry, append a
/// fresh testpaths line at the end of the file (TOML accepts duplicate
/// table headers in practice — pytest reads the first one). Operators
/// who already have a pytest config can hand-merge afterwards.
fn inject_testpaths(existing: &str) -> String {
    let mut out = existing.to_owned();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.contains(PYTEST_HEADER) {
        out.push_str("\n");
        out.push_str(PYTEST_HEADER);
        out.push('\n');
    }
    out.push_str(TESTPATHS_LINE);
    out.push('\n');
    out
}

// ---------------------------------------------------------------------
// Python invocation
// ---------------------------------------------------------------------

/// Build a `Command` that resolves to the available Python interpreter.
/// On Windows we try `python` then `python3`; on other OSes we still try
/// both because `python3` is the more common modern symlink.
fn python_command() -> Result<Command> {
    for candidate in ["python", "python3"] {
        if probe_python(candidate) {
            return Ok(Command::new(candidate));
        }
    }
    Err(harness_error(
        "python interpreter not found on PATH",
        "install Python 3.10+ and ensure `python` or `python3` is on PATH, then retry",
    ))
}

fn probe_python(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_regenerate(paths: &HarnessPaths) -> Result<RegenSummary> {
    let mut cmd = python_command()?;
    cmd.current_dir(paths.root.as_std_path())
        .arg(paths.regenerate_script.as_std_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().map_err(spawn_failure)?;
    if !output.status.success() {
        return Err(harness_error(
            format!(
                "regenerate failed (exit={:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            "fix the underlying Python error and re-run; missing pytest? `pip install pytest`",
        ));
    }
    Ok(RegenSummary::from_stdout(&output.stdout))
}

#[derive(Debug, Default, Clone)]
pub(crate) struct RegenSummary {
    signatures: usize,
    modules: usize,
    tries: usize,
}

impl RegenSummary {
    fn from_stdout(bytes: &[u8]) -> Self {
        let raw = String::from_utf8_lossy(bytes);
        let mut s = Self::default();
        for line in raw.lines() {
            s.absorb_line(line);
        }
        s
    }

    fn absorb_line(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix("wrote ") {
            self.absorb_wrote_prefix(rest);
        }
    }

    fn absorb_wrote_prefix(&mut self, rest: &str) {
        let mut tokens = rest.split_whitespace();
        let Some(count_str) = tokens.next() else {
            return;
        };
        let Ok(count) = count_str.parse::<usize>() else {
            return;
        };
        match tokens.next() {
            Some("signatures") => {
                self.signatures = count;
                self.modules = parse_across(rest);
            }
            Some("try-block") => {
                self.tries = count;
            }
            _ => {}
        }
    }
}

/// Pull the integer following `across ` in a regenerate-script summary
/// line — used to surface the imported-module count in the init banner.
fn parse_across(rest: &str) -> usize {
    let Some(after) = rest.split("across ").nth(1) else {
        return 0;
    };
    let Some(token) = after.split_whitespace().next() else {
        return 0;
    };
    token.parse::<usize>().unwrap_or(0)
}

fn print_init_summary(paths: &HarnessPaths, captured: RegenSummary) {
    let _ = writeln!(
        io::stderr(),
        "Harness initialised at {}\n  {} signatures captured across {} modules\n  {} try-blocks captured\n\nCommit `tests/cc_harness/` as the baseline.",
        paths.harness_dir, captured.signatures, captured.modules, captured.tries,
    );
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

fn spawn_failure(source: io::Error) -> CliError {
    CliError::Io {
        context: "harness_spawn",
        source,
    }
}

fn harness_error(what: impl Into<String>, action: &'static str) -> CliError {
    CliError::Harness {
        message: what.into(),
        action,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use tempfile::TempDir;

    #[test]
    fn pyproject_default_when_missing() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("pyproject.toml")).expect("utf8");
        update_pyproject(&path).expect("update");
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.contains("tests/cc_harness"));
        assert!(body.contains(PYTEST_HEADER));
    }

    #[test]
    fn pyproject_extends_existing_without_duplicating_when_already_present() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("pyproject.toml")).expect("utf8");
        std::fs::write(
            path.as_std_path(),
            "[tool.pytest.ini_options]\ntestpaths = [\"tests\", \"tests/cc_harness\"]\n",
        )
        .expect("seed");
        update_pyproject(&path).expect("idempotent update");
        let body = std::fs::read_to_string(&path).expect("read");
        let occurrences = body.matches("tests/cc_harness").count();
        assert_eq!(occurrences, 1, "must not duplicate the existing entry");
    }

    #[test]
    fn regen_summary_extracts_counts_from_stdout() {
        let stdout = b"wrote 12 signatures across 3 modules\nwrote 4 try-block shapes\nskipped 1 modules (missing externals)\n";
        let s = RegenSummary::from_stdout(stdout);
        assert_eq!(s.signatures, 12);
        assert_eq!(s.modules, 3);
        assert_eq!(s.tries, 4);
    }

    #[test]
    fn templates_include_the_seven_layers_and_helpers() {
        let names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        for required in [
            "_discovery.py",
            "_import_helper.py",
            "_signature_capture.py",
            "_exception_shape.py",
            "_dependency_capture.py",
            "_marker_capture.py",
            "_public_api_capture.py",
            "_suppression_capture.py",
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
        ] {
            assert!(names.contains(&required), "missing template: {required}");
        }
        for t in TEMPLATES {
            assert!(!t.body.is_empty(), "empty body for {}", t.name);
        }
    }
}
