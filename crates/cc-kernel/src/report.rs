//! [`KernelRunReport`] — the structured outcome of `Kernel::run`.
//!
//! The report is the *only* return type the CLI cares about: it carries
//! every finding, the deterministic [`HealthScore`], walk telemetry, and
//! per-rule timing for ad-hoc profiling.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use camino::Utf8PathBuf;
use cc_finding::Finding;
use cc_score::HealthScore;
use serde::{Deserialize, Serialize};

/// Per-rule wall-clock total across the whole run, keyed by `rule_id`.
pub type PerRuleTiming = BTreeMap<String, Duration>;

/// Outcome of a single `ccv12 check` invocation.
///
/// Serde-friendly so the CLI / LSP can dump the report verbatim to disk
/// or stream it to a daemon. `started_at` is wall-clock; `elapsed` is a
/// monotonic duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRunReport {
    /// Repo root the run scanned.
    pub root: Utf8PathBuf,
    /// Wall-clock start of the run.
    pub started_at: SystemTime,
    /// Total elapsed time, monotonic.
    pub elapsed: Duration,
    /// Number of files actually parsed + lifted.
    pub files_scanned: u32,
    /// Number of files walked but filtered out (ignore glob, size cap,
    /// unsupported extension, etc.).
    pub files_skipped: u32,
    /// Every finding produced by every rule, in run order.
    pub findings: Vec<Finding>,
    /// Deterministic health score.
    pub score: HealthScore,
    /// Wall-clock total per `rule_id` — useful for profiling rule packs.
    pub per_rule_timing: PerRuleTiming,
}

impl KernelRunReport {
    /// Convenience: total finding count.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Convenience: true iff any blocker-severity finding was produced.
    #[must_use]
    pub fn has_blocker(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == cc_finding::Severity::Blocker)
    }
}
