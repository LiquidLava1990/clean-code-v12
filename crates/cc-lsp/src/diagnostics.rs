//! [`cc_finding::Finding`] -> [`tower_lsp::lsp_types::Diagnostic`] conversion.
//!
//! Phase-1 mapping rules (frozen):
//!
//! | `Severity`           | `DiagnosticSeverity`              |
//! |----------------------|-----------------------------------|
//! | [`Severity::Blocker`]  | [`DiagnosticSeverity::ERROR`]       |
//! | [`Severity::Required`] | [`DiagnosticSeverity::WARNING`]     |
//! | [`Severity::Nit`]      | [`DiagnosticSeverity::INFORMATION`] |
//!
//! Findings carry 1-indexed positions; LSP wants 0-indexed positions, so
//! every line/column gets a `saturating_sub(1)`. Underflow is impossible
//! in correctly-emitted findings (line 0 is illegal in `Position::new`)
//! but the saturation guard means a malformed finding produces a clamped
//! diagnostic rather than panicking the daemon.

use cc_finding::{Finding, Severity};
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, NumberOrString, Position, Range};

/// Source label written into every emitted [`Diagnostic`].
///
/// Editors render this as the prefix in the squiggly tooltip
/// (e.g. `cc(R-FN-LEN): function exceeds 50 lines`). Stable across the
/// lifetime of the daemon so config UIs can filter by it.
pub const DIAGNOSTIC_SOURCE: &str = "ccv12";

/// Map a finding to an LSP diagnostic.
///
/// The mapping is total: every finding produces exactly one diagnostic.
/// Related locations, fix proposals, and dataflow paths are dropped in
/// Phase 1 (re-attached when code-action support lands in Phase 5).
#[must_use]
pub fn finding_to_diagnostic(finding: &Finding) -> Diagnostic {
    let range = location_to_range(&finding.location);
    let severity = Some(severity_to_diagnostic_severity(finding.severity));
    let code = Some(NumberOrString::String(finding.rule_id.to_string()));
    let message = format_message(finding);

    Diagnostic {
        range,
        severity,
        code,
        code_description: None,
        source: Some(DIAGNOSTIC_SOURCE.to_owned()),
        message,
        related_information: None,
        tags: None,
        data: None,
    }
}

/// Translate a [`cc_finding::Severity`] into the LSP enum.
#[must_use]
pub const fn severity_to_diagnostic_severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Blocker => DiagnosticSeverity::ERROR,
        Severity::Required => DiagnosticSeverity::WARNING,
        Severity::Nit => DiagnosticSeverity::INFORMATION,
    }
}

/// Convert a [`cc_finding::Location`] into an LSP [`Range`].
///
/// Findings store 1-indexed positions; LSP demands 0-indexed positions.
const fn location_to_range(loc: &cc_finding::Location) -> Range {
    Range {
        start: position_to_lsp(loc.start),
        end: position_to_lsp(loc.end),
    }
}

/// Convert one 1-indexed [`cc_finding::Position`] into a 0-indexed LSP
/// [`Position`]. Saturating to handle malformed input without panic.
const fn position_to_lsp(pos: cc_finding::Position) -> Position {
    Position {
        line: pos.line.saturating_sub(1),
        character: pos.column.saturating_sub(1),
    }
}

/// Build the human-readable message for a diagnostic.
///
/// Format: `"{headline}: {explanation}"` — explanations are short
/// (≤ 500 chars per the `ActionableMessage` contract) so a single
/// concatenated message fits the editor's hover budget.
fn format_message(finding: &Finding) -> String {
    let headline = finding.message.headline.trim();
    let explanation = finding.message.explanation.trim();
    if explanation.is_empty() {
        headline.to_owned()
    } else {
        format!("{headline}: {explanation}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use cc_finding::{
        ActionableMessage, Category, CostClaim, Evidence, FindingBuilder, Location, ProbeVersion,
        Remediation, Severity,
    };

    fn sample_finding(severity: Severity) -> Finding {
        FindingBuilder::new()
            .rule_id("R-FN-LEN")
            .category(Category::Shape)
            .location(Location {
                file: Utf8PathBuf::from("src/lib.rs"),
                start: cc_finding::Position::new(10, 5, 100),
                end: cc_finding::Position::new(12, 1, 200),
                node_id: None,
                function_qualified_name: None,
            })
            .message(ActionableMessage::new(
                "function exceeds 50 lines",
                "long functions are hard to test",
                Remediation::doc_link("https://example.invalid/r-fn-len"),
            ))
            .evidence(Evidence::from_snippet("fn long() { /* ... */ }"))
            .severity(severity)
            .confidence(1.0)
            .cost(CostClaim::BlockingDebt { weight: 5 })
            .probe_version(ProbeVersion::new("cc-test", "0.0.0", 1, None))
            .build()
            .expect("test finding builds")
    }

    #[test]
    fn maps_blocker_to_error() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Blocker));
        assert_eq!(diag.severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn maps_required_to_warning() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Required));
        assert_eq!(diag.severity, Some(DiagnosticSeverity::WARNING));
    }

    #[test]
    fn maps_nit_to_information() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Nit));
        assert_eq!(diag.severity, Some(DiagnosticSeverity::INFORMATION));
    }

    #[test]
    fn positions_are_zero_indexed() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Blocker));
        assert_eq!(diag.range.start.line, 9);
        assert_eq!(diag.range.start.character, 4);
        assert_eq!(diag.range.end.line, 11);
        assert_eq!(diag.range.end.character, 0);
    }

    #[test]
    fn source_and_code_set() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Blocker));
        assert_eq!(diag.source.as_deref(), Some("ccv12"));
        match &diag.code {
            Some(NumberOrString::String(s)) => assert_eq!(s, "R-FN-LEN"),
            other => panic!("expected string code, got {other:?}"),
        }
    }

    #[test]
    fn message_combines_headline_and_explanation() {
        let diag = finding_to_diagnostic(&sample_finding(Severity::Required));
        assert!(diag.message.contains("function exceeds 50 lines"));
        assert!(diag.message.contains("hard to test"));
    }
}
