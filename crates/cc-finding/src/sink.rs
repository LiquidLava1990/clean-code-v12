//! [`FindingSink`] trait + four reference implementations.
//!
//! - [`SarifSink`]   — stub (real impl in `cc-sarif`)
//! - [`RdJsonSink`]  — stub (real impl in `cc-rdformat`)
//! - [`TtySink`]     — colored terminal output (real)
//! - [`BaselineDiffSink`] — wraps another sink, drops baseline matches

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::Write;

use owo_colors::OwoColorize;

use crate::error::{FindingError, Result};
use crate::finding::Finding;
use crate::severity::Severity;
use crate::summary::Summary;
use crate::suppress::SuppressKey;

/// Trait implemented by every emission target.
///
/// Sinks are typically used like this:
///
/// ```ignore
/// let mut sink = TtySink::stderr();
/// for f in findings { sink.emit(f)?; }
/// let summary = sink.finish()?;
/// ```
pub trait FindingSink {
    /// Emit a single finding.
    ///
    /// # Errors
    /// Implementations bubble up I/O or serialisation errors.
    fn emit(&mut self, finding: Finding) -> Result<()>;

    /// Drain any buffered state and return the summary counters.
    ///
    /// # Errors
    /// Implementations bubble up I/O or serialisation errors.
    fn finish(self: Box<Self>) -> Result<Summary>;
}

// ---------------------------------------------------------------------------
// SARIF stub
// ---------------------------------------------------------------------------

/// Stub SARIF sink. The real implementation lives in `cc-sarif` —
/// keeping the type here lets crates wire trait objects without a
/// circular dependency.
#[derive(Debug, Default)]
pub struct SarifSink {
    summary: Summary,
}

impl SarifSink {
    /// Create an empty SARIF sink (stub).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl FindingSink for SarifSink {
    fn emit(&mut self, finding: Finding) -> Result<()> {
        self.summary.record(&finding);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Summary> {
        Ok(self.summary)
    }
}

// ---------------------------------------------------------------------------
// RDFormat stub
// ---------------------------------------------------------------------------

/// Stub `RDJson` sink. Real implementation lives in `cc-rdformat`.
#[derive(Debug, Default)]
pub struct RdJsonSink {
    summary: Summary,
}

impl RdJsonSink {
    /// Create an empty `RDJson` sink (stub).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl FindingSink for RdJsonSink {
    fn emit(&mut self, finding: Finding) -> Result<()> {
        self.summary.record(&finding);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Summary> {
        Ok(self.summary)
    }
}

// ---------------------------------------------------------------------------
// TTY sink
// ---------------------------------------------------------------------------

/// Colored, human-readable terminal sink.
///
/// The output is intentionally close to `cargo`/`rustc` style so the
/// findings drop into existing developer mental models.
pub struct TtySink {
    writer: Box<dyn Write + Send>,
    use_color: bool,
    summary: Summary,
}

impl std::fmt::Debug for TtySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtySink")
            .field("use_color", &self.use_color)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl TtySink {
    /// Build a TTY sink writing to stderr with auto-detected colour.
    #[must_use]
    pub fn stderr() -> Self {
        Self::new(Box::new(std::io::stderr()), true)
    }

    /// Build a TTY sink writing to stdout with auto-detected colour.
    #[must_use]
    pub fn stdout() -> Self {
        Self::new(Box::new(std::io::stdout()), true)
    }

    /// Build a TTY sink with a custom writer + explicit colour flag.
    #[must_use]
    pub fn new(writer: Box<dyn Write + Send>, use_color: bool) -> Self {
        Self {
            writer,
            use_color,
            summary: Summary::new(),
        }
    }

    /// Render a single finding to a string (used for tests + emit).
    #[must_use]
    pub fn render(&self, f: &Finding) -> String {
        let mut out = String::new();
        out.push_str(&render_header(f, self.use_color));
        out.push('\n');
        out.push_str(&render_location(f, self.use_color));
        out.push('\n');
        out.push_str(&render_explanation(f));
        out.push('\n');
        out.push_str(&render_remediation(f));
        out
    }
}

fn render_header(f: &Finding, color: bool) -> String {
    let sev = severity_tag(f.severity, color);
    let rule = if color {
        f.rule_id.bright_white().bold().to_string()
    } else {
        f.rule_id.to_string()
    };
    format!("{sev} {rule}: {}", f.message.headline)
}

fn severity_tag(sev: Severity, color: bool) -> String {
    if !color {
        return format!("[{}]", sev.as_str().to_ascii_uppercase());
    }
    match sev {
        Severity::Blocker => "[BLOCKER]".red().bold().to_string(),
        Severity::Required => "[REQUIRED]".yellow().bold().to_string(),
        Severity::Nit => "[NIT]".cyan().bold().to_string(),
    }
}

fn render_location(f: &Finding, color: bool) -> String {
    let loc = format!(
        "  --> {}:{}:{}",
        f.location.file, f.location.start.line, f.location.start.column
    );
    if color {
        loc.dimmed().to_string()
    } else {
        loc
    }
}

fn render_explanation(f: &Finding) -> String {
    format!("  {}", f.message.explanation)
}

fn render_remediation(f: &Finding) -> String {
    use crate::message::Remediation;
    match &f.message.remediation {
        Remediation::AutoFix(_) => "  fix: auto-fix available — run `ccv12 fix`".to_string(),
        Remediation::SuggestedRewrite(s) => format!("  fix: {s}"),
        Remediation::DocLink(url) => format!("  docs: {url}"),
        Remediation::Multiple(items) => {
            format!("  fix: {} options available", items.len())
        }
    }
}

impl FindingSink for TtySink {
    fn emit(&mut self, finding: Finding) -> Result<()> {
        let rendered = self.render(&finding);
        writeln!(self.writer, "{rendered}").map_err(|source| FindingError::Io {
            context: "TtySink::emit",
            source,
        })?;
        self.summary.record(&finding);
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Summary> {
        Ok(self.summary)
    }
}

// ---------------------------------------------------------------------------
// Baseline-diff sink
// ---------------------------------------------------------------------------

/// Wraps another sink, dropping any finding whose [`SuppressKey`] is in
/// the supplied baseline set.
///
/// Mirrors Semgrep's `--baseline-commit` model: existing findings are
/// silenced so reviewers see only what *new* code introduced.
pub struct BaselineDiffSink<S: FindingSink> {
    inner: S,
    baseline: HashSet<SuppressKey>,
    suppressed: RefCell<u32>,
}

impl<S: FindingSink + std::fmt::Debug> std::fmt::Debug for BaselineDiffSink<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaselineDiffSink")
            .field("inner", &self.inner)
            .field("baseline_size", &self.baseline.len())
            .field("suppressed", &*self.suppressed.borrow())
            .finish()
    }
}

impl<S: FindingSink> BaselineDiffSink<S> {
    /// Wrap `inner` with a baseline of suppress-keys to drop.
    #[must_use]
    pub const fn new(inner: S, baseline: HashSet<SuppressKey>) -> Self {
        Self {
            inner,
            baseline,
            suppressed: RefCell::new(0),
        }
    }

    /// Number of findings dropped because they matched the baseline.
    #[must_use]
    pub fn suppressed_count(&self) -> u32 {
        *self.suppressed.borrow()
    }
}

impl<S: FindingSink + 'static> FindingSink for BaselineDiffSink<S> {
    fn emit(&mut self, finding: Finding) -> Result<()> {
        if self.baseline.contains(&finding.suppress_key) {
            *self.suppressed.borrow_mut() += 1;
            return Ok(());
        }
        self.inner.emit(finding)
    }

    fn finish(self: Box<Self>) -> Result<Summary> {
        Box::new(self.inner).finish()
    }
}
