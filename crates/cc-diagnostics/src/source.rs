//! Origin classifier for a [`Diagnostic`].
//!
//! [`Source`] tells consumers *who* emitted the diagnostic so a
//! `--source pack` filter can isolate probe-pack noise from kernel
//! noise without code-string parsing.
//!
//! [`Diagnostic`]: crate::Diagnostic

use serde::{Deserialize, Serialize};

/// The kernel subsystem that produced a [`Diagnostic`].
///
/// `Other` is the escape hatch for out-of-tree integrations — the
/// `&'static str` is canonical (lower-snake-case) so dashboards can
/// group on it.
///
/// [`Diagnostic`]: crate::Diagnostic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Source {
    /// Boot, scheduler, salsa runtime.
    Kernel,
    /// Tree-sitter wrappers, parse error recovery.
    Frontend,
    /// Probe-pack manifest loader (`cc-rules` / `cc-rules-tier0`).
    Pack,
    /// Individual probe execution.
    Probe,
    /// Repo or user config file (`cc.toml`, `.cc/config`).
    Config,
    /// Score / aggregator layer.
    Score,
    /// Sink emit failure (SARIF / `RDFormat` / TTY).
    Sink,
    /// Anything not yet first-class. Tag must be lower-snake-case.
    Other(&'static str),
}

impl Source {
    /// Stable string used in metric labels and grouping keys.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Frontend => "frontend",
            Self::Pack => "pack",
            Self::Probe => "probe",
            Self::Config => "config",
            Self::Score => "score",
            Self::Sink => "sink",
            Self::Other(name) => name,
        }
    }
}
