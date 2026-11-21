//! Clap derive structs — the user-facing argument surface.
//!
//! Three subcommands: `check` (default when a path is supplied alone),
//! `init`, and `version`. Every option carries a short doc-comment so
//! `ccv12 --help` is self-documenting.

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand, ValueEnum};

/// Top-level CLI entry parsed by `clap`.
///
/// `ccv12 <PATH>` is sugar for `ccv12 check <PATH>` — the legacy short form
/// keeps muscle-memory from prior tools.
#[derive(Debug, Parser)]
#[command(
    name = "ccv12",
    version,
    about = "Clean Code V12 — find blockers, required fixes, and nits.",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Verbosity: -v → info, -vv → debug. Falls back to `RUST_LOG`.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Subcommand.
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run every Tier-0 rule against `path` and emit findings.
    Check(CheckArgs),
    /// Drop a default `.cc/config.toml` + empty baseline.
    Init(InitArgs),
    /// Create / inspect / sync / clear the persisted baseline file.
    Baseline(BaselineArgs),
    /// Apply machine-applicable `Remediation::AutoFix` edits in place.
    Fix(FixArgs),
    /// Scaffold + run the 7-layer pre-refactor safety harness.
    Harness(HarnessArgs),
    /// Print the CLI + kernel version string.
    Version,
}

/// Arguments accepted by `ccv12 harness <SUB>`.
///
/// The harness is the test-first / pre-refactor gate: scaffold the
/// seven-layer drift + slop safety net (imports, public signatures,
/// exception-handler shapes, dependencies, slop markers, public API,
/// suppressions); verify it stays green; regenerate after deliberate
/// changes.
#[derive(Debug, Parser)]
pub struct HarnessArgs {
    /// Subcommand: init | verify | regenerate.
    #[command(subcommand)]
    pub cmd: HarnessCmd,
}

/// `ccv12 harness` subcommands.
#[derive(Debug, Subcommand)]
pub enum HarnessCmd {
    /// Scaffold `tests/cc_harness/` and capture the baseline snapshot.
    Init(HarnessInitArgs),
    /// Run `python -m pytest tests/cc_harness/` and surface drift.
    Verify(HarnessVerifyArgs),
    /// Re-run the regenerate script to ratify a deliberate API change.
    Regenerate(HarnessRegenerateArgs),
}

/// Arguments accepted by `ccv12 harness init`.
#[derive(Debug, Parser)]
pub struct HarnessInitArgs {
    /// Repository root to scaffold. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
}

/// Arguments accepted by `ccv12 harness verify`.
#[derive(Debug, Parser)]
pub struct HarnessVerifyArgs {
    /// Repository root to verify. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
}

/// Arguments accepted by `ccv12 harness regenerate`.
#[derive(Debug, Parser)]
pub struct HarnessRegenerateArgs {
    /// Repository root containing the harness. Defaults to `.`.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
}

/// Arguments accepted by `ccv12 check`.
#[derive(Debug, Parser)]
pub struct CheckArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Tty)]
    pub format: OutputFormat,

    /// Diff-mode: silence findings already accepted in the baseline JSON.
    ///
    /// `--baseline-from` is an alias accepted for symmetry with
    /// `ccv12 baseline create --output` and parity with Semgrep's
    /// `--baseline-commit` ergonomics.
    #[arg(long, alias = "baseline-from", value_name = "BASELINE_PATH")]
    pub baseline: Option<Utf8PathBuf>,

    /// Restrict to a comma-separated list of rule ids.
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    pub rules: Vec<String>,

    /// Minimum severity to display (`blocker`, `required`, `nit`).
    #[arg(long, value_enum, default_value_t = SeverityFilter::Nit)]
    pub severity: SeverityFilter,

    /// Skip registration of `BuiltinTier0Pack`.
    #[arg(long)]
    pub no_default_pack: bool,

    /// Write to `FILE` instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<Utf8PathBuf>,
}

/// Arguments accepted by `ccv12 fix`.
///
/// Mirrors `ccv12 check`'s `--severity` / `--rule` filters so operators can
/// scope a repair pass to a single rule (`--rule cc.shape.fn_length`)
/// or severity floor without learning a new flag surface.
#[derive(Debug, Parser)]
pub struct FixArgs {
    /// Repository root to scan + repair. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,

    /// Print "would fix N findings in M files" but do not write anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Restrict to a comma-separated list of rule ids.
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    pub rules: Vec<String>,

    /// Minimum severity to consider (`blocker`, `required`, `nit`).
    #[arg(long, value_enum, default_value_t = SeverityFilter::Nit)]
    pub severity: SeverityFilter,

    /// Skip registration of `BuiltinTier0Pack`.
    #[arg(long)]
    pub no_default_pack: bool,
}

/// Arguments accepted by `ccv12 init`.
#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Directory in which to create `.cc/config.toml` + `.cc/baseline.json`.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,

    /// Overwrite an existing `.cc/config.toml` if present.
    #[arg(long)]
    pub force: bool,
}

/// Output format for `ccv12 check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Colored, human-readable terminal output (default).
    Tty,
    /// SARIF 2.1.0 JSON document.
    Sarif,
    /// Reviewdog `RDJSON` line-delimited stream.
    Rdjson,
    /// Plain JSON line-stream of `Finding`s — one per line.
    Json,
}

/// Severity filter for `--severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityFilter {
    /// Display all findings.
    Nit,
    /// Drop nits — show only `Required` and `Blocker`.
    Required,
    /// Show only `Blocker` findings.
    Blocker,
}

impl SeverityFilter {
    /// Map the filter to a `cc_finding::Severity` floor.
    #[must_use]
    pub const fn min_severity(self) -> cc_finding::Severity {
        match self {
            Self::Nit => cc_finding::Severity::Nit,
            Self::Required => cc_finding::Severity::Required,
            Self::Blocker => cc_finding::Severity::Blocker,
        }
    }
}

/// Arguments accepted by `ccv12 baseline <SUB>`.
///
/// The subcommand mirrors `Semgrep --baseline-commit` ergonomics + the
/// `detect-secrets baseline {scan,audit}` workflow: a small CRUD surface
/// over a JSON file the operator commits alongside `.cc/config.toml`.
#[derive(Debug, Parser)]
pub struct BaselineArgs {
    /// Subcommand: create | status | sync | clear.
    #[command(subcommand)]
    pub cmd: BaselineCmd,
}

/// `ccv12 baseline` subcommands.
#[derive(Debug, Subcommand)]
pub enum BaselineCmd {
    /// Run `ccv12 check` and persist every observed finding as the new
    /// baseline file. Findings already in the file are kept (with their
    /// acceptance metadata); new findings get freshly-stamped entries.
    Create(BaselineCreateArgs),
    /// Print "X in baseline, Y still present, Z resolved since last sync"
    /// without mutating the file. Read-only — safe in CI.
    Status(BaselineStatusArgs),
    /// Re-run `ccv12 check` and prune resolved entries from the baseline
    /// file in place. Atomic — temp-then-rename.
    Sync(BaselineSyncArgs),
    /// Wipe the baseline file. Prompts for confirmation unless `--yes`.
    Clear(BaselineClearArgs),
}

/// Arguments accepted by `ccv12 baseline create`.
#[derive(Debug, Parser)]
pub struct BaselineCreateArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
    /// Where to write the baseline file. Defaults to
    /// `<PATH>/.cc-baseline.json` (Semgrep-style root sentinel).
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<Utf8PathBuf>,
    /// Skip registration of `BuiltinTier0Pack` (mirrors `ccv12 check`).
    #[arg(long)]
    pub no_default_pack: bool,
    /// Free-form note recorded on every newly accepted entry
    /// (`"legacy code, fix in M2"`).
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
    /// Reviewer attribution recorded on every newly accepted entry.
    /// Defaults to `"cc-cli"` so the audit trail is never empty.
    #[arg(long, value_name = "WHO")]
    pub who: Option<String>,
}

/// Arguments accepted by `ccv12 baseline status`.
#[derive(Debug, Parser)]
pub struct BaselineStatusArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
    /// Path to the baseline file. Defaults to `<PATH>/.cc-baseline.json`.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<Utf8PathBuf>,
    /// Skip registration of `BuiltinTier0Pack` (mirrors `ccv12 check`).
    #[arg(long)]
    pub no_default_pack: bool,
}

/// Arguments accepted by `ccv12 baseline sync`.
#[derive(Debug, Parser)]
pub struct BaselineSyncArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
    /// Path to the baseline file. Defaults to `<PATH>/.cc-baseline.json`.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<Utf8PathBuf>,
    /// Skip registration of `BuiltinTier0Pack` (mirrors `ccv12 check`).
    #[arg(long)]
    pub no_default_pack: bool,
    /// Print the planned diff but do NOT mutate the baseline file.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments accepted by `ccv12 baseline clear`.
#[derive(Debug, Parser)]
pub struct BaselineClearArgs {
    /// Repository root containing the baseline. Defaults to `.`.
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: Utf8PathBuf,
    /// Path to the baseline file. Defaults to `<PATH>/.cc-baseline.json`.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<Utf8PathBuf>,
    /// Skip the interactive confirmation prompt. Required for non-TTY
    /// callers (CI). Mirrors `rm -f` semantics.
    #[arg(long)]
    pub yes: bool,
}
