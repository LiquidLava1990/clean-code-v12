//! Severity [`Level`] for kernel/pack [`Diagnostic`] values.
//!
//! Distinct from `cc_finding::Severity`: this enum classifies *operator*
//! visibility (what the kernel itself wants to log), not user-code
//! findings. `--verbose` typically gates `Trace`/`Debug`.
//!
//! [`Diagnostic`]: crate::Diagnostic

use serde::{Deserialize, Serialize};

/// Operator-visibility level for a [`Diagnostic`].
///
/// Mirrors `tracing::Level` so the [`TracingSink`] can map 1:1 without
/// translation tables.
///
/// [`Diagnostic`]: crate::Diagnostic
/// [`TracingSink`]: crate::TracingSink
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Per-node walker noise; off by default.
    Trace,
    /// Per-rule book-keeping; on with `-vv`.
    Debug,
    /// Lifecycle events (probe loaded, pack registered).
    Info,
    /// Recoverable problem (one rule degraded, continuing).
    Warn,
    /// Hard failure visible to operators (probe panic, config reject).
    Error,
}

impl Level {
    /// Static label suitable for log prefixes and CLI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}
