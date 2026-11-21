//! `cc.modernize.deprecated_unwrap` — Rust `.unwrap()` outside test files.
//!
//! Mirrors clippy `unwrap_used`. Detection: any [`NodeKind::Call`] whose
//! canonical callee text contains `.unwrap` and lives in a `.rs` source
//! file outside the conventional test paths.
//!
//! Severity: `Required` — `.unwrap()` panics on `None` / `Err` and erases
//! the actionable error context. Use `?`, `expect("<context>")`, or an
//! explicit match.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.deprecated_unwrap`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeprecatedUnwrapRule;

impl Rule for DeprecatedUnwrapRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.deprecated_unwrap"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "Rust `.unwrap()` outside test files"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    if !looks_like_unwrap(&text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !path.as_str().ends_with(".rs") {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.deprecated_unwrap",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: "`.unwrap()` panics with no context — use `?` or `expect`".into(),
        explanation: "`.unwrap()` panics on `None` / `Err` and erases the \
             error path: production logs read `called Option::unwrap()` with \
             no hint at the actual cause. `?` propagates the error, \
             `expect(\"<context>\")` panics with a message, and \
             `match` / `if let` keeps the code total."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `.unwrap()` with `?` (when the function returns Result), \
             `expect(\"explain why infallible\")` (when truly infallible), or \
             a `match` / `if let Some(..)` (when the None case has logic)."
                .into(),
        ),
        snippet: text,
        weight: 2,
    }))
}

fn looks_like_unwrap(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    text.contains(".unwrap")
        || text.ends_with("::unwrap")
        || text == "unwrap"
        || text.contains(" unwrap ")
}
