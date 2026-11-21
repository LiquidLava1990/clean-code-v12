//! `cc.type.unjustified_ignore` — flag type-checker silencing comments
//! that lack a justification clause.
//!
//! Per-language markers (see [`crate::helpers::IGNORE_MARKERS`]):
//!
//! - Python: `# type: ignore`, `# pyright: ignore`, `# noqa`
//! - TypeScript: `// @ts-ignore`, `// @ts-expect-error`
//! - Go: `// nolint`, `//nolint`
//! - Rust: `#[allow(...)]`
//!
//! For each `Comment` node whose text begins with one of those markers,
//! the rule inspects the trailing 80 characters on the same line for
//! any of these justification shapes:
//!
//! - `: <reason>` — colon-introduced explanation
//! - `# <reason>` / `// <reason>` — comment-style explanation
//! - `because <text>` — natural-language justification
//! - `bug <bug-id>` — issue reference
//!
//! Empty tail = silent silencing = flag.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, TypesFindingBlueprint, IGNORE_MARKERS,
};

/// Family-22 probe R-TYPE-UNJUSTIFIED-IGNORE.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnjustifiedIgnoreRule;

/// Maximum bytes of trailing comment text scanned for a justification.
const TAIL_WINDOW: usize = 80;

impl Rule for UnjustifiedIgnoreRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.unjustified_ignore"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "type-checker / linter silencing marker without a stated reason"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Comment) {
            if let Some(finding) = check_comment(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_comment(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = comment_text(ctx, id)?;
    let (marker, _lang) = match_marker(text)?;
    let tail = trailing_after_marker(text, marker);
    if has_justification(tail, marker) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.unjustified_ignore",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{marker}` without a stated reason"),
        explanation: format!(
            "Silencing the type checker / linter without a written reason \
             converts a real warning into invisible technical debt. The \
             marker `{marker}` carries no justification on the same line."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Append a short reason on the same line, e.g. `{marker}: bug \
             #1234 — upstream fix tracked` or `{marker} because the \
             tree-sitter binding emits a non-Send type we cannot wrap`."
        )),
        snippet: text.to_owned(),
        weight: 1,
    }))
}

fn comment_text<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    string_prop(ctx.batch, id, "text").or_else(|| string_prop(ctx.batch, id, "value"))
}

fn match_marker(text: &str) -> Option<(&'static str, &'static str)> {
    let trimmed = text.trim_start();
    for (marker, lang) in IGNORE_MARKERS {
        if trimmed.starts_with(marker) {
            return Some((*marker, *lang));
        }
    }
    None
}

fn trailing_after_marker<'a>(text: &'a str, marker: &str) -> &'a str {
    let trimmed = text.trim_start();
    let after = trimmed.get(marker.len()..).unwrap_or("");
    let line_end = after.find('\n').unwrap_or(after.len());
    let window_end = line_end.min(TAIL_WINDOW);
    after.get(..window_end).unwrap_or("")
}

fn has_justification(tail: &str, marker: &str) -> bool {
    if marker == "#[allow(" {
        return rust_allow_has_reason(tail);
    }
    let cleaned = tail.trim();
    if cleaned.is_empty() {
        return false;
    }
    if let Some(rest) = cleaned.strip_prefix(':') {
        return !rest.trim().is_empty();
    }
    if let Some(rest) = cleaned.strip_prefix('#') {
        return !rest.trim().is_empty();
    }
    if let Some(rest) = cleaned.strip_prefix("//") {
        return !rest.trim().is_empty();
    }
    let lower = cleaned.to_ascii_lowercase();
    lower.contains("because") || lower.contains("bug ") || lower.contains("issue ")
}

fn rust_allow_has_reason(tail: &str) -> bool {
    // `#[allow(dead_code, reason = "..." )]` style — Rust 1.81+ supports
    // an explicit `reason = ...` clause inside the lint list. Anything
    // else (a bare `#[allow(dead_code)]`) is unjustified.
    let lower = tail.to_ascii_lowercase();
    lower.contains("reason =") || lower.contains("reason=")
}
