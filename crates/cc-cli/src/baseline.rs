//! `cc baseline` subcommand — Section-4 Tooling-Gap-#18 helper.
//!
//! Mirrors the Semgrep `--baseline-commit` workflow plus the
//! `detect-secrets baseline {scan,audit}` ergonomics: a 4-verb CRUD over
//! a JSON file the operator commits next to `.cc/config.toml`.
//!
//! - `cc baseline create [PATH]` — run `cc check`, persist every
//!   observed finding into `<root>/.cc-baseline.json`. Already-accepted
//!   entries keep their reviewer / reason / `accepted_at` metadata.
//! - `cc baseline status` — read-only report: total entries, still
//!   present, resolved-since-last-sync. Safe in CI.
//! - `cc baseline sync` — rerun + drop resolved entries (atomic write).
//!   `--dry-run` prints the diff without mutating the file.
//! - `cc baseline clear` — wipe the file (interactive confirm unless
//!   `--yes`).
//!
//! # Baseline integration in `cc check`
//!
//! `cc check --baseline <FILE>` (alias `--baseline-from`) ALREADY filters
//! findings whose `SuppressKey` is present in the baseline file — see
//! [`crate::runner::run_check`] → `apply_baseline`. This module is a CLI
//! wrapper around the same `cc-baseline` repo type; it does **not**
//! duplicate the load+filter step.
//!
//! # Forever rules atop
//! - Functions ≤50 LOC, nesting ≤3, no `unwrap()` in production paths.
//! - Atomic writes via [`cc_baseline::repo::BaselineRepo::save`] (temp +
//!   rename — kill-9 safe).
//! - Errors carry remediation hints (R-ERR-ACTION).

use std::io::{self, BufRead, IsTerminal, Write};

use camino::{Utf8Path, Utf8PathBuf};
use cc_baseline::{apply, BaselineRepo, DiffOutcome};
use cc_finding::{Finding, SuppressKey};
use cc_kernel::KernelRunReport;

use crate::args::{
    BaselineArgs, BaselineClearArgs, BaselineCmd, BaselineCreateArgs, BaselineStatusArgs,
    BaselineSyncArgs,
};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::runner::{build_kernel, canonicalise_root, load_or_default_config};

/// Default baseline filename — committed at the repo root, sibling to
/// `.cc/config.toml`. Matches the Semgrep / detect-secrets convention of
/// a single-file root sentinel.
pub const DEFAULT_BASELINE_FILE: &str = ".cc-baseline.json";

/// Plain summary printed by `cc baseline status` and returned by
/// [`baseline_status_for`]. Public so library callers can drive the
/// status check without spawning the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineStatus {
    /// Total entries in the on-disk baseline file.
    pub total_in_baseline: usize,
    /// Entries whose `SuppressKey` was re-observed by the latest run.
    pub still_present: usize,
    /// Entries the latest run did NOT re-observe — prune candidates.
    pub resolved: usize,
    /// Findings emitted by the latest run that are NOT in the baseline.
    pub new_findings: usize,
}

/// Top-level dispatcher for `cc baseline <SUB>`.
///
/// # Errors
/// Surfaces every [`CliError`] variant — invalid root, config load
/// failure, kernel runtime failure, or baseline I/O.
pub fn run_baseline(args: &BaselineArgs) -> Result<ExitCode> {
    match &args.cmd {
        BaselineCmd::Create(a) => run_baseline_create(a),
        BaselineCmd::Status(a) => run_baseline_status(a),
        BaselineCmd::Sync(a) => run_baseline_sync(a),
        BaselineCmd::Clear(a) => run_baseline_clear(a),
    }
}

/// Resolve the on-disk baseline path: explicit override, else the
/// repo-root sentinel `<root>/.cc-baseline.json`.
fn resolve_baseline_path(root: &Utf8Path, explicit: Option<&Utf8Path>) -> Utf8PathBuf {
    if let Some(rel) = explicit {
        if rel.is_absolute() {
            rel.to_path_buf()
        } else {
            root.join(rel)
        }
    } else {
        root.join(DEFAULT_BASELINE_FILE)
    }
}

/// Open (or initialise empty) the baseline at `path`, mapping the
/// underlying error to [`CliError::Baseline`].
fn open_baseline(path: &Utf8Path) -> Result<BaselineRepo> {
    BaselineRepo::open(path).map_err(|source| CliError::Baseline {
        path: path.to_path_buf(),
        source,
    })
}

/// Save `repo` to `path`, mapping I/O errors to [`CliError::Baseline`].
fn save_baseline(repo: &BaselineRepo, path: &Utf8Path) -> Result<()> {
    repo.save(path).map_err(|source| CliError::Baseline {
        path: path.to_path_buf(),
        source,
    })
}

/// Run the kernel against `root` and return the produced report.
/// Mirrors `runner::run_check` minus the sink + severity filter (we
/// keep every finding so the baseline captures the full picture).
fn run_kernel(root: &Utf8Path, no_default_pack: bool) -> Result<KernelRunReport> {
    let config = load_or_default_config(root)?;
    let kernel = build_kernel(config, no_default_pack)?;
    kernel
        .run(root)
        .map_err(|source| CliError::Kernel { source })
}

/// Implements `cc baseline create`.
///
/// Strategy: open existing baseline (or empty), accept every finding,
/// then save atomically. Existing entries are touched (`seen_count++`,
/// `last_seen_at = now`), preserving reviewer attribution.
///
/// # Errors
/// Surfaces the kernel + baseline I/O errors verbatim.
pub fn run_baseline_create(args: &BaselineCreateArgs) -> Result<ExitCode> {
    let root = canonicalise_root(&args.path)?;
    let path = resolve_baseline_path(&root, args.output.as_deref());
    let report = run_kernel(&root, args.no_default_pack)?;

    let mut repo = open_baseline(&path)?;
    let who = args.who.clone().or_else(|| Some("cc-cli".to_owned()));
    let inserted = accept_all(&mut repo, &report.findings, args.reason.clone(), who);

    save_baseline(&repo, &path)?;
    print_create_summary(&path, &repo, &report, inserted);
    Ok(ExitCode::Clean)
}

/// Accept every finding in `findings` into `repo`, returning the count
/// of newly inserted (vs. touched) entries.
fn accept_all(
    repo: &mut BaselineRepo,
    findings: &[Finding],
    reason: Option<String>,
    who: Option<String>,
) -> usize {
    let mut inserted = 0usize;
    for finding in findings {
        if repo.accept(finding, reason.clone(), who.clone()) {
            inserted += 1;
        }
    }
    inserted
}

fn print_create_summary(
    path: &Utf8Path,
    repo: &BaselineRepo,
    report: &KernelRunReport,
    inserted: usize,
) {
    let total = repo.len();
    let observed = report.findings.len();
    let _ = writeln!(
        io::stderr(),
        "baseline written: {path}\n  observed {observed} findings · {inserted} new entries · {total} total in baseline"
    );
}

/// Common pre-amble for every subcommand that needs (root, baseline
/// path, kernel report). Extracted to keep `status` / `sync` from
/// duplicating each other (cc.shape.duplication).
struct ScanCtx {
    path: Utf8PathBuf,
    findings: Vec<Finding>,
}

fn scan_for(
    repo_root: &Utf8Path,
    explicit_baseline: Option<&Utf8Path>,
    no_default_pack: bool,
) -> Result<ScanCtx> {
    let root = canonicalise_root(repo_root)?;
    let path = resolve_baseline_path(&root, explicit_baseline);
    let report = run_kernel(&root, no_default_pack)?;
    Ok(ScanCtx {
        path,
        findings: report.findings,
    })
}

/// Implements `cc baseline status`. Read-only — never mutates the file.
///
/// # Errors
/// Surfaces the kernel + baseline I/O errors verbatim.
pub fn run_baseline_status(args: &BaselineStatusArgs) -> Result<ExitCode> {
    let ctx = scan_for(&args.path, args.baseline.as_deref(), args.no_default_pack)?;
    let status = baseline_status_for(&ctx.path, &ctx.findings)?;
    print_status_summary(&ctx.path, &status);
    Ok(if status.new_findings == 0 {
        ExitCode::Clean
    } else {
        ExitCode::Findings
    })
}

/// Compute a [`BaselineStatus`] for the baseline at `path` against the
/// supplied finding stream. Pure-ish — only mutates a clone of the repo
/// (the disk file is untouched).
///
/// # Errors
/// Returns [`CliError::Baseline`] for I/O / parse failures.
pub fn baseline_status_for(path: &Utf8Path, findings: &[Finding]) -> Result<BaselineStatus> {
    let mut repo = open_baseline(path)?;
    let total = repo.len();
    let outcome = apply(&mut repo, findings);
    Ok(BaselineStatus {
        total_in_baseline: total,
        still_present: outcome.persisted.len(),
        resolved: outcome.escaped.len(),
        new_findings: outcome.new.len(),
    })
}

fn print_status_summary(path: &Utf8Path, s: &BaselineStatus) {
    let _ = writeln!(io::stderr(), "baseline: {path}");
    let _ = writeln!(
        io::stderr(),
        "  {} findings in baseline, {} still present, {} resolved since last sync",
        s.total_in_baseline,
        s.still_present,
        s.resolved
    );
    let _ = writeln!(
        io::stderr(),
        "  {} new findings (not yet baselined)",
        s.new_findings
    );
}

/// Implements `cc baseline sync`.
///
/// Touches every persisted entry, then removes resolved entries and
/// writes the baseline back atomically. `--dry-run` prints the diff
/// without saving.
///
/// # Errors
/// Surfaces the kernel + baseline I/O errors verbatim.
pub fn run_baseline_sync(args: &BaselineSyncArgs) -> Result<ExitCode> {
    let ctx = scan_for(&args.path, args.baseline.as_deref(), args.no_default_pack)?;
    let mut repo = open_baseline(&ctx.path)?;
    let total_before = repo.len();
    let outcome = apply(&mut repo, &ctx.findings);
    let resolved_keys = drop_resolved(&mut repo, &outcome);
    if !args.dry_run {
        save_baseline(&repo, &ctx.path)?;
    }
    print_sync_summary(
        &ctx.path,
        total_before,
        &outcome,
        &resolved_keys,
        args.dry_run,
    );
    Ok(ExitCode::Clean)
}

/// Remove every key in `outcome.escaped` from `repo`. Returns the
/// removed keys in iteration order (stable for review diffs).
fn drop_resolved(repo: &mut BaselineRepo, outcome: &DiffOutcome) -> Vec<SuppressKey> {
    if outcome.escaped.is_empty() {
        return Vec::new();
    }
    repo.remove_keys(&outcome.escaped)
}

fn print_sync_summary(
    path: &Utf8Path,
    total_before: usize,
    outcome: &DiffOutcome,
    resolved_keys: &[SuppressKey],
    dry_run: bool,
) {
    let header = if dry_run { "[dry-run] " } else { "" };
    let _ = writeln!(io::stderr(), "{header}baseline sync: {path}");
    let _ = writeln!(
        io::stderr(),
        "  {} entries before · {} persisted · {} resolved (removed) · {} new findings (not added)",
        total_before,
        outcome.persisted.len(),
        resolved_keys.len(),
        outcome.new.len()
    );
}

/// Implements `cc baseline clear`. Refuses to act on a non-TTY without
/// `--yes` so a stuck CI pipeline cannot lose data on a hung prompt.
///
/// # Errors
/// Surfaces baseline I/O errors verbatim.
pub fn run_baseline_clear(args: &BaselineClearArgs) -> Result<ExitCode> {
    let root = canonicalise_root(&args.path)?;
    let path = resolve_baseline_path(&root, args.baseline.as_deref());

    if !path.exists() {
        let _ = writeln!(io::stderr(), "baseline already absent: {path}");
        return Ok(ExitCode::Clean);
    }

    if !args.yes && !confirm_clear(&path)? {
        let _ = writeln!(io::stderr(), "aborted; baseline left in place: {path}");
        return Ok(ExitCode::Clean);
    }

    let empty = BaselineRepo::empty();
    save_baseline(&empty, &path)?;
    let _ = writeln!(io::stderr(), "baseline cleared: {path}");
    Ok(ExitCode::Clean)
}

/// Interactive `y/N` prompt. Refuses on non-TTY (caller must pass
/// `--yes`), mapping the refusal to [`CliError::Io`] so the operator
/// gets an actionable message.
fn confirm_clear(path: &Utf8Path) -> Result<bool> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(CliError::Io {
            context: "baseline_clear_prompt",
            source: io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "stdin is not a TTY but `--yes` was not supplied; \
                     re-run `cc baseline clear --yes` to wipe `{path}` non-interactively"
                ),
            ),
        });
    }
    let _ = write!(io::stderr(), "wipe baseline at `{path}`? [y/N] ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    let read = stdin
        .lock()
        .read_line(&mut line)
        .map_err(|source| CliError::Io {
            context: "baseline_clear_prompt_read",
            source,
        })?;
    if read == 0 {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cc_baseline::Baseline as BaselineModel;
    use cc_finding::{
        ActionableMessage, Category, CostClaim, Evidence, Finding, FindingBuilder, Location,
        NodeId, Position, ProbeVersion, Remediation, Severity,
    };
    use tempfile::TempDir;

    fn sample_location(node: &str, qual: &str) -> Location {
        Location {
            file: Utf8PathBuf::from("src/foo.rs"),
            start: Position::new(10, 4, 120),
            end: Position::new(15, 1, 240),
            node_id: Some(NodeId::new(node)),
            function_qualified_name: Some(qual.to_owned()),
        }
    }

    fn sample_message() -> ActionableMessage {
        ActionableMessage::new(
            "synthetic finding",
            "test fixture",
            Remediation::doc_link("https://cleancode.dev/test"),
        )
    }

    fn sample_evidence(snippet: &str) -> Evidence {
        Evidence::from_snippet(snippet)
    }

    fn synth_finding(rule_id: &'static str, qual: &str, snippet: &str) -> Finding {
        FindingBuilder::new()
            .rule_id(rule_id)
            .category(Category::Shape)
            .location(sample_location(qual, qual))
            .message(sample_message())
            .evidence(sample_evidence(snippet))
            .severity(Severity::Required)
            .confidence(0.9)
            .cost(CostClaim::BlockingDebt { weight: 5 })
            .probe_version(ProbeVersion::new("cc-tier0", "0.1.0", 1, None))
            .build()
            .expect("synthetic finding builds")
    }

    fn baseline_path(tmp: &TempDir) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(tmp.path().join(DEFAULT_BASELINE_FILE)).expect("utf8 tempdir")
    }

    fn write_baseline_with(tmp: &TempDir, findings: &[Finding]) -> Utf8PathBuf {
        let path = baseline_path(tmp);
        let mut repo = BaselineRepo::empty();
        for f in findings {
            repo.accept(f, Some("test".into()), Some("tester".into()));
        }
        repo.save(&path).expect("save");
        path
    }

    #[test]
    fn create_then_load_round_trip_preserves_count() {
        let tmp = TempDir::new().expect("tempdir");
        let f1 = synth_finding("cc.shape.fn_length", "mod::a", "def a(): pass");
        let f2 = synth_finding("cc.shape.fn_length", "mod::b", "def b(): pass");
        let path = write_baseline_with(&tmp, &[f1.clone(), f2.clone()]);

        let repo = open_baseline(&path).expect("open");
        assert_eq!(repo.len(), 2);
        assert!(repo.contains(&f1.suppress_key));
        assert!(repo.contains(&f2.suppress_key));
    }

    #[test]
    fn baseline_file_is_parseable_json_with_expected_shape() {
        let tmp = TempDir::new().expect("tempdir");
        let f = synth_finding("cc.shape.fn_length", "mod::z", "def z(): pass");
        let path = write_baseline_with(&tmp, &[f]);
        let bytes = std::fs::read(&path).expect("read");
        let parsed: BaselineModel = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed.schema_version, cc_baseline::SCHEMA_VERSION);
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn status_partitions_present_resolved_new_correctly() {
        let tmp = TempDir::new().expect("tempdir");
        let baselined = synth_finding("cc.shape.fn_length", "mod::keep", "def keep(): pass");
        let resolved = synth_finding("cc.shape.fn_length", "mod::gone", "def gone(): pass");
        let path = write_baseline_with(&tmp, &[baselined.clone(), resolved.clone()]);

        let new_finding = synth_finding("cc.shape.fn_length", "mod::new", "def new(): pass");
        let findings = [baselined.clone(), new_finding];

        let status = baseline_status_for(&path, &findings).expect("status");
        assert_eq!(status.total_in_baseline, 2);
        assert_eq!(status.still_present, 1);
        assert_eq!(status.resolved, 1);
        assert_eq!(status.new_findings, 1);
    }

    #[test]
    fn sync_removes_resolved_entries_and_keeps_persisted() {
        let tmp = TempDir::new().expect("tempdir");
        let keep = synth_finding("cc.shape.fn_length", "mod::keep", "def keep(): pass");
        let drop_me = synth_finding("cc.shape.fn_length", "mod::gone", "def gone(): pass");
        let path = write_baseline_with(&tmp, &[keep.clone(), drop_me.clone()]);

        let mut repo = open_baseline(&path).expect("open");
        let outcome = apply(&mut repo, &[keep.clone()]);
        assert_eq!(outcome.escaped.len(), 1);
        let removed = drop_resolved(&mut repo, &outcome);
        assert_eq!(removed.len(), 1);
        assert!(removed.contains(&drop_me.suppress_key));
        assert!(repo.contains(&keep.suppress_key));
        assert_eq!(repo.len(), 1);
    }

    #[test]
    fn clear_with_yes_replaces_with_empty_baseline() {
        let tmp = TempDir::new().expect("tempdir");
        let f = synth_finding("cc.shape.fn_length", "mod::a", "def a(): pass");
        let path = write_baseline_with(&tmp, &[f]);

        let args = BaselineClearArgs {
            path: Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8"),
            baseline: None,
            yes: true,
        };
        let code = run_baseline_clear(&args).expect("clear");
        assert_eq!(code, ExitCode::Clean);
        let repo = open_baseline(&path).expect("re-open");
        assert!(repo.is_empty());
    }

    #[test]
    fn clear_skips_when_file_absent() {
        let tmp = TempDir::new().expect("tempdir");
        let args = BaselineClearArgs {
            path: Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8"),
            baseline: None,
            yes: true,
        };
        let code = run_baseline_clear(&args).expect("noop clear");
        assert_eq!(code, ExitCode::Clean);
        assert!(!baseline_path(&tmp).exists());
    }

    #[test]
    fn resolve_baseline_path_uses_root_sentinel_by_default() {
        let root = Utf8PathBuf::from("/tmp/repo");
        let p = resolve_baseline_path(&root, None);
        assert_eq!(p, root.join(DEFAULT_BASELINE_FILE));
    }

    #[test]
    fn resolve_baseline_path_respects_absolute_override() {
        let root = Utf8PathBuf::from("/tmp/repo");
        let abs = Utf8PathBuf::from(if cfg!(windows) {
            "C:/abs/bl.json"
        } else {
            "/abs/bl.json"
        });
        let p = resolve_baseline_path(&root, Some(&abs));
        assert_eq!(p, abs);
    }

    #[test]
    fn resolve_baseline_path_joins_relative_override_to_root() {
        let root = Utf8PathBuf::from("/tmp/repo");
        let rel = Utf8PathBuf::from("custom/spot.json");
        let p = resolve_baseline_path(&root, Some(&rel));
        assert_eq!(p, root.join("custom/spot.json"));
    }

    #[test]
    fn cc_check_apply_filters_baselined_findings() {
        // Documents the load+filter integration that already lives in
        // `runner::apply_baseline`. `cc_baseline::apply` (the function
        // `cc check --baseline` calls) silences baselined findings while
        // letting fresh ones through.
        let tmp = TempDir::new().expect("tempdir");
        let baselined = synth_finding(
            "cc.shape.fn_length",
            "mod::silenced",
            "def silenced(): pass",
        );
        let path = write_baseline_with(&tmp, &[baselined.clone()]);

        let mut repo = open_baseline(&path).expect("open");
        let new_finding = synth_finding("cc.shape.fn_length", "mod::loud", "def loud(): pass");
        let outcome = apply(&mut repo, &[baselined.clone(), new_finding.clone()]);
        assert_eq!(outcome.new.len(), 1);
        assert_eq!(outcome.new[0].suppress_key, new_finding.suppress_key);
        assert_eq!(outcome.persisted.len(), 1);
        assert_eq!(outcome.persisted[0].suppress_key, baselined.suppress_key);
    }
}
