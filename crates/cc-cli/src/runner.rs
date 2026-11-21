//! Top-level `run` dispatcher: parse → build kernel → emit.
//!
//! The binary stays small by deferring almost everything to the helpers
//! in this module. All public functions return [`crate::error::Result`]
//! so the caller can map each `Err` onto a [`crate::ExitCode`].

use std::io::{self, Write};

use camino::{Utf8Path, Utf8PathBuf};
use cc_baseline::BaselineRepo;
use cc_config::Config;
use cc_finding::{Finding, FindingSink, Severity};
use cc_kernel::{Kernel, KernelRunReport};
use owo_colors::OwoColorize;

use crate::args::{CheckArgs, Cli, Cmd, InitArgs, OutputFormat, SeverityFilter};
use crate::error::{CliError, Result};
use crate::exit::ExitCode;
use crate::format::sink_for;

const CONFIG_REL_PATH: &str = ".cc/config.toml";
const BASELINE_REL_PATH: &str = ".cc/baseline.json";

/// Top-level dispatcher. Returns the [`ExitCode`] the binary should
/// surface to the OS — never panics on user input.
#[must_use]
pub fn run(cli: Cli) -> ExitCode {
    init_tracing(cli.verbose);
    match cli.cmd {
        Cmd::Check(args) => unwrap_exit(run_check(&args)),
        Cmd::Init(args) => unwrap_exit(run_init(&args).map(|()| ExitCode::Clean)),
        Cmd::Baseline(args) => unwrap_exit(crate::baseline::run_baseline(&args)),
        Cmd::Fix(args) => unwrap_exit(crate::fix::run_fix(&args)),
        Cmd::Harness(args) => unwrap_exit(crate::harness::run_harness(&args)),
        Cmd::Version => {
            print_version();
            ExitCode::Clean
        }
    }
}

/// Map a subcommand `Result<ExitCode>` onto the OS-facing [`ExitCode`],
/// rendering the error to stderr with R-ERR-ACTION sources walked.
fn unwrap_exit(result: Result<ExitCode>) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(err) => report_error(&err),
    }
}

/// Configure `tracing-subscriber` based on `--verbose` count.
fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(io::stderr)
        .try_init();
}

/// Print the diagnostic for `err` to stderr and return the matching
/// [`ExitCode`].
fn report_error(err: &CliError) -> ExitCode {
    let _ = writeln!(io::stderr(), "error: {err}");
    let mut source: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(s) = source {
        let _ = writeln!(io::stderr(), "  caused by: {s}");
        source = s.source();
    }
    ExitCode::RuntimeError
}

/// Run `ccv12 check`.
///
/// # Errors
///
/// Surfaces every [`CliError`] variant — invalid root, config load
/// failure, kernel runtime failure, sink finalisation error, or
/// baseline I/O error. The caller is expected to render the error and
/// map the [`Err`] onto [`ExitCode::RuntimeError`].
pub fn run_check(args: &CheckArgs) -> Result<ExitCode> {
    let root = canonicalise_root(&args.path)?;
    let config = load_or_default_config(&root)?;
    let kernel = build_kernel(config, args.no_default_pack)?;

    let mut sink = sink_for(args.format, args.output.as_deref())?;
    let report = kernel
        .run_with_sink(&root, dispatch_filter_sink(&mut *sink, args).as_mut())
        .map_err(|source| CliError::Kernel { source })?;

    finalise_sink(sink)?;
    let report = apply_baseline(report, args.baseline.as_deref(), &root)?;
    print_summary(&report, args.format);

    Ok(classify_exit(&report, args.severity))
}

/// Map `path` onto an absolute root, validating it exists. Shared by
/// every subcommand that needs a repo root (check, baseline).
pub(crate) fn canonicalise_root(path: &Utf8Path) -> Result<Utf8PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir_utf8()?.join(path)
    };
    if !absolute.is_dir() {
        return Err(CliError::InvalidRoot { path: absolute });
    }
    Ok(absolute)
}

/// Read `std::env::current_dir` and lift it into `Utf8PathBuf`, surfacing
/// either an IO failure or a non-UTF-8-cwd error as [`CliError::Io`].
pub(crate) fn current_dir_utf8() -> Result<Utf8PathBuf> {
    let cwd = std::env::current_dir().map_err(|source| CliError::Io {
        context: "current_dir",
        source,
    })?;
    Utf8PathBuf::from_path_buf(cwd).map_err(|bad| CliError::Io {
        context: "cwd_not_utf8",
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cwd is not valid UTF-8: {}", bad.display()),
        ),
    })
}

/// Load `.cc/config.toml` if present, else use [`Config::default_for_repo`].
pub(crate) fn load_or_default_config(root: &Utf8Path) -> Result<Config> {
    let path = root.join(CONFIG_REL_PATH);
    if path.exists() {
        Ok(Config::load(&path)?)
    } else {
        Ok(Config::default_for_repo(root))
    }
}

/// Build a kernel and (optionally) register the default Tier-0 pack.
pub(crate) fn build_kernel(config: Config, no_default_pack: bool) -> Result<Kernel> {
    let mut kernel = Kernel::new(config)?;
    if !no_default_pack {
        kernel.with_default_packs()?;
    }
    Ok(kernel)
}

/// Wrap the user sink with an optional severity / rule-id filter.
fn dispatch_filter_sink<'s>(
    inner: &'s mut dyn FindingSink,
    args: &CheckArgs,
) -> Box<dyn FindingSink + 's> {
    Box::new(FilterSink {
        inner,
        min_severity: args.severity.min_severity(),
        rule_allow: if args.rules.is_empty() {
            None
        } else {
            Some(args.rules.clone())
        },
    })
}

/// Finalise the underlying sink (drops buffered SARIF output, flushes
/// JSON lines, etc.). Errors map to [`CliError::SinkFinish`].
fn finalise_sink(sink: Box<dyn FindingSink>) -> Result<()> {
    sink.finish()
        .map(|_| ())
        .map_err(|source| CliError::SinkFinish { source })
}

/// Diff the run report against an optional baseline file.
///
/// When `baseline` is `Some`, the returned report's `findings` are the
/// NEW findings only (anything matching a baseline `suppress_key` is
/// silenced). The score and counts are NOT recomputed — Phase 1 keeps
/// the original score so the operator still sees the absolute health.
fn apply_baseline(
    mut report: KernelRunReport,
    baseline: Option<&Utf8Path>,
    root: &Utf8Path,
) -> Result<KernelRunReport> {
    let Some(rel) = baseline else {
        return Ok(report);
    };
    let path = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let mut repo = BaselineRepo::open(&path).map_err(|source| CliError::Baseline {
        path: path.clone(),
        source,
    })?;
    let outcome = cc_baseline::apply(&mut repo, &report.findings);
    report.findings = outcome.new;
    Ok(report)
}

/// Print the closing health summary to stderr (so it doesn't pollute a
/// SARIF / JSON document on stdout).
fn print_summary(report: &KernelRunReport, format: OutputFormat) {
    if matches!(
        format,
        OutputFormat::Sarif | OutputFormat::Rdjson | OutputFormat::Json
    ) {
        // Machine formats: stay silent. Operators parse the doc itself.
        return;
    }
    let counts = &report.score.finding_counts;
    let bl = format!("{} Blocker", counts.blocker);
    let rq = format!("{} Required", counts.required);
    let nt = format!("{} Nit", counts.nit);
    let line = format!(
        "Health: {}/100  ({} · {} · {})",
        report.score.score, bl, rq, nt
    );
    let elapsed = report.elapsed.as_secs_f32();
    let footer = format!(
        "Scanned {} files in {:.2}s ({} skipped)",
        report.files_scanned, elapsed, report.files_skipped
    );
    let _ = writeln!(io::stderr(), "\n{}", line.bold());
    let _ = writeln!(io::stderr(), "{}", footer.dimmed());
}

/// Decide the final exit code from the report + severity filter.
fn classify_exit(report: &KernelRunReport, severity: SeverityFilter) -> ExitCode {
    let floor = severity.min_severity();
    let any = report
        .findings
        .iter()
        .any(|f| f.severity.rank() >= floor.rank());
    if any {
        ExitCode::Findings
    } else {
        ExitCode::Clean
    }
}

/// Print `ccv12 <cli-version> (kernel <kernel-version>)`.
fn print_version() {
    let cli_version = env!("CARGO_PKG_VERSION");
    let _ = writeln!(io::stdout(), "ccv12 {cli_version} (kernel {cli_version})");
}

/// Run `ccv12 init`.
///
/// # Errors
///
/// Returns [`CliError::ConfigExists`] when the target already has a
/// config and `--force` was not supplied, [`CliError::Io`] for
/// directory-creation failures, [`CliError::Config`] from
/// [`cc_config::write_default`], or [`CliError::Baseline`] when the
/// initial empty baseline cannot be written.
pub fn run_init(args: &InitArgs) -> Result<()> {
    let root = if args.path.as_str() == "." {
        current_dir_utf8()?
    } else {
        args.path.clone()
    };
    std::fs::create_dir_all(root.as_std_path()).map_err(|source| CliError::Io {
        context: "create_dir_all",
        source,
    })?;

    let config_path = root.join(CONFIG_REL_PATH);
    if config_path.exists() && !args.force {
        return Err(CliError::ConfigExists { path: config_path });
    }
    cc_config::write_default(&config_path)?;

    let baseline_path = root.join(BASELINE_REL_PATH);
    if !baseline_path.exists() {
        let repo = BaselineRepo::empty();
        repo.save(&baseline_path)
            .map_err(|source| CliError::Baseline {
                path: baseline_path,
                source,
            })?;
    }
    Ok(())
}

/// Sink wrapper that drops findings below `min_severity` or outside
/// `rule_allow`.
///
/// Lives here (not in `cc-finding`) because the filter policy is purely
/// CLI-shaped — kernel + sinks should stay format-neutral.
struct FilterSink<'s> {
    inner: &'s mut dyn FindingSink,
    min_severity: Severity,
    rule_allow: Option<Vec<String>>,
}

impl FindingSink for FilterSink<'_> {
    fn emit(&mut self, finding: Finding) -> cc_finding::Result<()> {
        if finding.severity.rank() < self.min_severity.rank() {
            return Ok(());
        }
        if let Some(allow) = &self.rule_allow {
            if !allow.iter().any(|id| id == finding.rule_id.as_ref()) {
                return Ok(());
            }
        }
        self.inner.emit(finding)
    }

    fn finish(self: Box<Self>) -> cc_finding::Result<cc_finding::Summary> {
        // The CLI calls finish() on the wrapped sink directly; this
        // wrapper short-circuits because `&mut dyn` cannot be moved.
        Ok(cc_finding::Summary::new())
    }
}
