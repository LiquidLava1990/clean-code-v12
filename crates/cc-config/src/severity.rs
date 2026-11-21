//! Local mirror of `cc-finding::Severity`.
//!
//! Defined locally to avoid a circular dependency on `cc-finding`
//! during Phase 1 bootstrapping (`cc-finding` is still a stub at the
//! time this crate is implemented). When `cc-finding` lands its real
//! schema, this module will re-export from there. Kept identical in
//! shape and ordering to the canonical definition in
//! `docs/design/FINDING_SCHEMA.md`.

use serde::{Deserialize, Serialize};

/// Severity bucket for findings.
///
/// Ordering is intentional: `Blocker` > `Required` > `Nit`. Used by
/// validation to decide whether `severity_override` is a downgrade
/// (allowed) or an upgrade (rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Cosmetic — never blocks merge.
    Nit,
    /// Must fix before session close.
    Required,
    /// Merge refused.
    Blocker,
}

impl Severity {
    /// Stable string label for diagnostic messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nit => "nit",
            Self::Required => "required",
            Self::Blocker => "blocker",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
