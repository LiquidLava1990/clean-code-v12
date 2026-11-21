//! `RDJSON` document types.
//!
//! Mirror the reviewdog `DiagnosticResult` JSON schema 1:1. Field naming
//! follows the canonical `RDFormat` wire format (`camelCase` on the wire,
//! `snake_case` in Rust).
//!
//! Reference:
//! <https://github.com/reviewdog/reviewdog/blob/master/proto/rdf/jsonschema/DiagnosticResult.jsonschema>

use serde::{Deserialize, Serialize};

/// One reviewdog diagnostic — corresponds to a single `cc-finding`
/// [`cc_finding::Finding`] after [`fn@crate::to_rdjson`] mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdJsonDiagnostic {
    /// Headline + remediation summary (R-ERR-ACTION dogfood).
    pub message: String,
    /// Primary location pointing at the offending range.
    pub location: RdLocation,
    /// Severity — drives reviewdog's PR-comment styling.
    pub severity: RdSeverity,
    /// The tool that produced the diagnostic.
    pub source: RdSource,
    /// Stable rule id + doc URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<RdCode>,
    /// Machine-applicable suggestions (Safe diffs only).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggestions: Vec<RdSuggestion>,
    /// Original tool output line — left empty by `cc-finding`.
    #[serde(rename = "original_output", skip_serializing_if = "Option::is_none")]
    pub original_output: Option<String>,
}

/// File path + range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdLocation {
    /// Project-relative path. Forward slashes on every OS.
    pub path: String,
    /// Source range covered by the diagnostic.
    pub range: RdRange,
}

/// Inclusive `[start, end]` source range (`RDFormat` is closed on both
/// ends because reviewdog GitHub posting is line-oriented).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdRange {
    /// Start position.
    pub start: RdPosition,
    /// End position.
    pub end: RdPosition,
}

/// 1-indexed line/column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdPosition {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed column number.
    pub column: u32,
}

/// Reviewdog severity — wire-format strings are `ERROR | WARNING | INFO`
/// per the `RDFormat` schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RdSeverity {
    /// Hardest level — maps from [`cc_finding::Severity::Blocker`].
    Error,
    /// Mid-level — maps from [`cc_finding::Severity::Required`].
    Warning,
    /// Soft level — maps from [`cc_finding::Severity::Nit`].
    Info,
}

/// The producing tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdSource {
    /// Human-readable tool name, e.g. `"clean-code-v12"`.
    pub name: String,
    /// Tool homepage URL.
    pub url: String,
}

/// Rule id + optional doc URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdCode {
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`.
    pub value: String,
    /// Optional doc-link URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// One auto-applicable suggestion (mapped from `FixProposal::Diff
/// { safety: Safe }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdSuggestion {
    /// Range to replace.
    pub range: RdRange,
    /// Replacement text.
    pub text: String,
}

// ---------------------------------------------------------------------------
// SourceMeta — tool identity
// ---------------------------------------------------------------------------

/// Identity of the producing tool, plumbed into every diagnostic.
///
/// Held by [`crate::sink::RdJsonSink`] and threaded through
/// [`fn@crate::to_rdjson`]. `'static` borrowed strings keep the
/// hot-path zero-alloc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceMeta {
    /// Tool display name, e.g. `"clean-code-v12"`.
    pub name: &'static str,
    /// Tool homepage URL.
    pub url: &'static str,
    /// Doc-link base — `<doc_base_url>/<family>/<rule_id>.md` is the
    /// per-rule documentation pointer.
    pub doc_base_url: &'static str,
}

impl SourceMeta {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(name: &'static str, url: &'static str, doc_base_url: &'static str) -> Self {
        Self {
            name,
            url,
            doc_base_url,
        }
    }

    /// Default identity used by Clean-Code-V12 itself.
    #[must_use]
    pub const fn clean_code_v12() -> Self {
        Self::new(
            "clean-code-v12",
            "https://github.com/LiquidLava1990/clean-code-v12",
            "https://docs.clean-code-v12.dev/rules",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rd_severity_serialises_uppercase() {
        let v = serde_json::to_value(RdSeverity::Error).unwrap();
        assert_eq!(v, serde_json::json!("ERROR"));
        let v = serde_json::to_value(RdSeverity::Warning).unwrap();
        assert_eq!(v, serde_json::json!("WARNING"));
        let v = serde_json::to_value(RdSeverity::Info).unwrap();
        assert_eq!(v, serde_json::json!("INFO"));
    }
}
