//! `cc.docs.docstring_coverage` — flag public-visibility functions
//! whose preceding three lines carry no doc-comment.
//!
//! "Public" means `is_pub == true` / `is_export == true` /
//! `visibility == "public"`. The rule is a Nit — production codebases
//! routinely ship internal-but-exported helpers that don't merit
//! prose; the user can suppress per-rule via config when this is the
//! house style.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_public_function, is_test_file_path, location_from_node,
    preceding_comment, DocsFindingBlueprint, COMMENT_LANG_PREFIXES,
};

/// Maximum line gap between the doc-comment's last line and the
/// function's start line for the rule to count the function as
/// documented.
const MAX_COVERAGE_GAP: u32 = 3;

/// Family-16 probe R-DOCS-DOCSTRING-COVERAGE.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocstringCoverageRule;

impl Rule for DocstringCoverageRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.docstring_coverage"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "public function has no preceding doc-comment"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, function_id: NodeId) -> Option<Finding> {
    if !is_public_function(ctx.batch, function_id) {
        return None;
    }
    if has_doc_comment(ctx.batch, function_id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, function_id)?;
    if is_test_file_path(&path) {
        // Test-file public surface is consumed by the test runner /
        // fixture harness; missing prose docs are not a coverage gap.
        return None;
    }
    let location = location_from_node(ctx.batch, function_id, path);
    let name = string_prop(ctx.batch, function_id, "name").unwrap_or("<anonymous>");
    Some(build_finding(DocsFindingBlueprint {
        rule_id: "cc.docs.docstring_coverage",
        severity: Severity::Nit,
        confidence: Confidence::new(0.75),
        location,
        headline: format!("public `{name}` has no doc-comment"),
        explanation: format!(
            "Public function `{name}` carries no preceding doc-comment \
             within {MAX_COVERAGE_GAP} source lines. Public callers \
             cannot infer intent from a name alone — document what the \
             function does, when to call it, and what it returns."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a doc-comment immediately above the function. Use the \
             language's idiomatic style (`///` Rust, `\"\"\"...\"\"\"` \
             Python, `/** ... */` JSDoc / JavaDoc)."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

/// True iff the function has a preceding [`NodeKind::Comment`] within
/// [`MAX_COVERAGE_GAP`] lines whose text starts with one of the known
/// doc-comment prefixes.
fn has_doc_comment(batch: &CpgWriteBatch, function_id: NodeId) -> bool {
    // `preceding_comment` returns *any* comment within the gap; we
    // tighten it here by also requiring a doc-prefix. Plain `//`
    // counts as a doc-comment for coverage purposes — the rule is a
    // Nit and rejecting `//` would over-fire on Rust internals.
    let Some(comment_id) = preceding_comment(batch, function_id, MAX_COVERAGE_GAP) else {
        return false;
    };
    if !comment_is_close_above(batch, comment_id, function_id) {
        return false;
    }
    let Some(text) =
        string_prop(batch, comment_id, "text").or_else(|| string_prop(batch, comment_id, "value"))
    else {
        return false;
    };
    let trimmed = text.trim_start();
    COMMENT_LANG_PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// Confirm the comment ends *before* the function starts (not after,
/// not overlapping). `preceding_comment` already filters by line gap
/// but does not guarantee directionality on degenerate ranges.
fn comment_is_close_above(batch: &CpgWriteBatch, comment_id: NodeId, function_id: NodeId) -> bool {
    let Some(comment_range) = range_prop(batch, comment_id, "range") else {
        return false;
    };
    let Some(function_range) = range_prop(batch, function_id, "range") else {
        return false;
    };
    comment_range.end.line <= function_range.start.line
}
