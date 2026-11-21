//! [`ActionableMessage`] + [`Remediation`] — the R-ERR-ACTION shape
//! enforced on every Finding.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::fix::FixProposal;

/// "What is wrong / why it matters / how to fix" — the three required
/// halves of every human-readable finding message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionableMessage {
    /// One-line "what is wrong" — should fit in < 80 characters.
    pub headline: String,
    /// Multi-sentence "why it matters" — should fit in < 500 characters.
    pub explanation: String,
    /// "How to fix" — must be present on every finding.
    pub remediation: Remediation,
}

impl ActionableMessage {
    /// Construct an actionable message. Lengths are not enforced at
    /// construction; the lint pack `cc.meta.message_length` validates
    /// them post-emission.
    #[must_use]
    pub fn new(
        headline: impl Into<String>,
        explanation: impl Into<String>,
        remediation: Remediation,
    ) -> Self {
        Self {
            headline: headline.into(),
            explanation: explanation.into(),
            remediation,
        }
    }
}

/// How to repair the code that triggered a Finding.
///
/// Every Finding **must** carry one. No bare "X is bad" without a "do Y."
/// This is the dogfood of R-ERR-ACTION on our own outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Remediation {
    /// Machine-applicable fix.
    AutoFix(FixProposal),
    /// Human-applied diff hint as a free-form string.
    SuggestedRewrite(String),
    /// Pointer to the rule documentation.
    DocLink(Cow<'static, str>),
    /// Combination of the above (e.g. autofix + doc link).
    Multiple(Vec<Remediation>),
}

impl Remediation {
    /// Construct a [`Remediation::DocLink`] from a static literal.
    #[must_use]
    pub const fn doc_link(url: &'static str) -> Self {
        Self::DocLink(Cow::Borrowed(url))
    }

    /// Return the first auto-applicable [`FixProposal`] anywhere in the
    /// remediation tree, if any.
    #[must_use]
    pub fn first_auto_fix(&self) -> Option<&FixProposal> {
        match self {
            Self::AutoFix(fp) if fp.is_auto_applicable() => Some(fp),
            Self::Multiple(items) => items.iter().find_map(Self::first_auto_fix),
            _ => None,
        }
    }
}
