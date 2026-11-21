//! Pure-function mapping from [`cc_finding::Finding`] to
//! [`crate::doc::RdJsonDiagnostic`].
//!
//! Lossy on `confidence`, `cost`, `evidence.cpg_node_dump`, and
//! `related` locations — `RDFormat` carries one location per diagnostic.
//! SARIF (in `cc-sarif`) is the lossless archive of record.

use cc_finding::{
    Finding, FixProposal, FixSafety, Range as FindingRange, Remediation, Severity, TextEdit,
};

use crate::doc::{
    RdCode, RdJsonDiagnostic, RdLocation, RdPosition, RdRange, RdSeverity, RdSource, RdSuggestion,
    SourceMeta,
};

/// Map a [`Finding`] to an [`RdJsonDiagnostic`].
///
/// The transform is total + side-effect-free; serialisation lives in
/// [`crate::sink::RdJsonSink`].
#[must_use]
pub fn to_rdjson(finding: &Finding, source_meta: SourceMeta) -> RdJsonDiagnostic {
    RdJsonDiagnostic {
        message: build_message(finding),
        location: build_location(finding),
        severity: severity_to_rd(finding.severity),
        source: build_source(source_meta),
        code: Some(build_code(finding, source_meta)),
        suggestions: build_suggestions(finding),
        original_output: None,
    }
}

fn build_source(meta: SourceMeta) -> RdSource {
    RdSource {
        name: meta.name.to_owned(),
        url: meta.url.to_owned(),
    }
}

/// Convert a [`Severity`] to its `RDFormat` counterpart.
#[must_use]
pub const fn severity_to_rd(severity: Severity) -> RdSeverity {
    match severity {
        Severity::Blocker => RdSeverity::Error,
        Severity::Required => RdSeverity::Warning,
        Severity::Nit => RdSeverity::Info,
    }
}

fn build_message(f: &Finding) -> String {
    let headline = f.message.headline.as_str();
    let remediation = remediation_summary(&f.message.remediation);
    if remediation.is_empty() {
        headline.to_owned()
    } else {
        format!("{headline} \u{2014} {remediation}")
    }
}

fn remediation_summary(r: &Remediation) -> String {
    match r {
        Remediation::AutoFix(fix) => fix_summary(fix),
        Remediation::SuggestedRewrite(text) => format!("suggested rewrite: {text}"),
        Remediation::DocLink(url) => format!("see docs: {url}"),
        Remediation::Multiple(items) => items
            .iter()
            .map(remediation_summary)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
    }
}

fn fix_summary(fix: &FixProposal) -> String {
    match fix {
        FixProposal::Diff { safety, edits, .. } => match safety {
            FixSafety::Safe => format!("auto-fix available ({} edit(s))", edits.len()),
            FixSafety::Unsafe => "unsafe fix available — run `ccv12 fix --unsafe`".to_owned(),
        },
        FixProposal::Codemod { engine, scope, .. } => {
            format!("codemod available (engine={engine:?}, scope={scope:?})")
        }
        FixProposal::LlmRewrite { rationale, .. } => format!("LLM rewrite suggested: {rationale}"),
    }
}

fn build_location(f: &Finding) -> RdLocation {
    RdLocation {
        path: f.location.file.as_str().replace('\\', "/"),
        range: RdRange {
            start: RdPosition {
                line: f.location.start.line,
                column: f.location.start.column,
            },
            end: RdPosition {
                line: f.location.end.line,
                column: f.location.end.column,
            },
        },
    }
}

fn build_code(f: &Finding, meta: SourceMeta) -> RdCode {
    RdCode {
        value: f.rule_id.as_ref().to_owned(),
        url: Some(rule_doc_url(&f.rule_id, meta.doc_base_url)),
    }
}

/// Derive the doc URL from a rule id of the form `cc.<family>.<slug>`.
///
/// Examples:
/// - `"cc.shape.fn_length"` -> `"<base>/shape/cc.shape.fn_length.md"`
/// - `"cc.taint.sql_injection"` -> `"<base>/taint/cc.taint.sql_injection.md"`
/// - unparseable -> `"<base>/<rule_id>.md"`
fn rule_doc_url(rule_id: &str, base: &str) -> String {
    let trimmed_base = base.trim_end_matches('/');
    let family = rule_id
        .strip_prefix("cc.")
        .and_then(|rest| rest.split('.').next())
        .unwrap_or("");
    if family.is_empty() {
        format!("{trimmed_base}/{rule_id}.md")
    } else {
        format!("{trimmed_base}/{family}/{rule_id}.md")
    }
}

fn build_suggestions(f: &Finding) -> Vec<RdSuggestion> {
    f.fix.as_ref().map_or_else(Vec::new, suggestions_from_fix)
}

fn suggestions_from_fix(fix: &FixProposal) -> Vec<RdSuggestion> {
    match fix {
        FixProposal::Diff {
            edits,
            safety: FixSafety::Safe,
            ..
        } => edits.iter().map(text_edit_to_suggestion).collect(),
        FixProposal::Diff {
            safety: FixSafety::Unsafe,
            ..
        }
        | FixProposal::LlmRewrite { .. } => Vec::new(),
        FixProposal::Codemod {
            pattern,
            replacement,
            ..
        } => codemod_suggestion(pattern, replacement),
    }
}

const fn codemod_suggestion(pattern: &str, replacement: &str) -> Vec<RdSuggestion> {
    // Codemods are pattern-based; without a concrete `[start, end]` range
    // we cannot emit a faithful RDJSON suggestion. Skip unless a future
    // codemod variant exposes a preview range.
    let _ = (pattern, replacement);
    Vec::new()
}

fn text_edit_to_suggestion(edit: &TextEdit) -> RdSuggestion {
    RdSuggestion {
        range: range_to_rd(edit.range),
        text: edit.new_text.clone(),
    }
}

const fn range_to_rd(range: FindingRange) -> RdRange {
    RdRange {
        start: RdPosition {
            line: range.start.line,
            column: range.start.column,
        },
        end: RdPosition {
            line: range.end.line,
            column: range.end.column,
        },
    }
}

#[cfg(test)]
#[path = "to_rdjson_tests.rs"]
mod tests;
