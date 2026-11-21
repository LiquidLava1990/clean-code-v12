//! LLM response shapes — [`Judgment`] for classifier probes,
//! [`RewriteProposal`] for rewrite probes.

use serde::{Deserialize, Serialize};

/// Verdict from a binary-classifier prompt (slop, comment-drift, etc.).
///
/// `confidence` is in `[0.0, 1.0]`. Probe authors should map low
/// confidence to `Severity::Nit` and only escalate to `Required` when
/// confidence clears a documented threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
pub enum Judgment {
    /// LLM judged the input acceptable.
    Clean {
        /// Confidence in `[0.0, 1.0]`.
        confidence: f32,
    },
    /// LLM judged the input low-quality / "slop".
    Slop {
        /// Confidence in `[0.0, 1.0]`.
        confidence: f32,
        /// Brief operator-facing reason.
        reason: String,
    },
    /// LLM declined to commit either way.
    Unsure,
}

impl Judgment {
    /// Confidence as a single scalar regardless of variant.
    /// `Unsure` returns `0.0`.
    #[must_use]
    pub const fn confidence(&self) -> f32 {
        match self {
            Self::Clean { confidence } | Self::Slop { confidence, .. } => *confidence,
            Self::Unsure => 0.0,
        }
    }
}

/// Concrete rewrite proposed by a rewrite-class probe.
///
/// `before` and `after` are the literal substrings (not full files);
/// the kernel maps them back to text edits via `cc-finding::TextEdit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteProposal {
    /// Original substring the LLM proposes replacing.
    pub before: String,
    /// Replacement substring.
    pub after: String,
    /// One-paragraph justification surfaced to the developer.
    pub explanation: String,
}
