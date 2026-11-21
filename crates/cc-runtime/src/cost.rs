//! Runtime cost data — what a profiler observed for a function or
//! call-site.
//!
//! Phase 4 fills these in from pprof / OTLP / collapsed-stack input.
//! Phase 1 ships the data shape so probes can already declare a
//! dependency on `RuntimeView` and downgrade gracefully when no
//! profile is attached.

use serde::{Deserialize, Serialize};

/// Wall-clock CPU time spent inside a function/site, in seconds.
///
/// `f64` so summed pprof samples do not lose precision for short
/// hot-spots; aggregator code converts to milliseconds at the
/// presentation boundary.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
pub struct CpuTime(pub f64);

/// Bytes allocated by a function/site during the profile window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Allocations(pub u64);

/// Aggregated runtime cost for a single function or call-site.
///
/// Probes consult this to ground static findings in observed cost
/// (e.g. only flag a "deeply nested loop" if `cpu_seconds` is in the
/// top decile of the profile).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default, Serialize, Deserialize)]
pub struct RuntimeCost {
    /// CPU seconds spent in this function/site (self time).
    pub cpu_seconds: f64,

    /// Bytes allocated (heap) during the profile window.
    pub allocations_bytes: u64,

    /// Number of times the function was entered / site was hit.
    pub call_count: u64,

    /// 99th-percentile latency in milliseconds, when the profile
    /// includes per-call timing (OTLP). `None` for plain pprof input.
    pub p99_latency_ms: Option<f64>,
}

impl RuntimeCost {
    /// Construct a [`RuntimeCost`] from individual fields.
    #[must_use]
    pub const fn new(
        cpu_seconds: f64,
        allocations_bytes: u64,
        call_count: u64,
        p99_latency_ms: Option<f64>,
    ) -> Self {
        Self {
            cpu_seconds,
            allocations_bytes,
            call_count,
            p99_latency_ms,
        }
    }

    /// `true` when *any* dimension of the cost is non-zero.
    ///
    /// Useful for downgrading findings: a static probe may want to
    /// skip a flag when the runtime witness reports zero hits.
    #[must_use]
    pub const fn is_observed(&self) -> bool {
        self.cpu_seconds > 0.0 || self.allocations_bytes > 0 || self.call_count > 0
    }
}
