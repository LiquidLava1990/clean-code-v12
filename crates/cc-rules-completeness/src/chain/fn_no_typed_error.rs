//! `cc.chain.fn_no_typed_error` — public fn body contains `raise` /
//! `throw` / `Err` of an untyped error.
//!
//! Heuristic: scan the function's source text for the bare patterns
//! `raise Exception(`, `throw new Error(`, `Err(anyhow!`, etc.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, is_public_fn,
    is_top_level_fn, location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.chain.fn_no_typed_error`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FnNoTypedErrorRule;

const UNTYPED_RAISE_NEEDLES: &[&str] = &[
    "raise Exception(",
    "raise BaseException(",
    "raise RuntimeError(",
    "throw new Error(",
    "Err(anyhow!",
    "anyhow::anyhow!",
    "panic!(\"",
];

impl Rule for FnNoTypedErrorRule {
    fn rule_id(&self) -> &'static str {
        "cc.chain.fn_no_typed_error"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "public fn raises an untyped error"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_fn(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_top_level_fn(ctx.batch, id) || !is_public_fn(ctx.batch, id) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source)?;
    if !body_contains_any(&body, UNTYPED_RAISE_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.chain.fn_no_typed_error",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("public fn `{name}` raises an untyped error"),
        explanation: "Public functions that raise generic Exception/Error/anyhow break \
             the function → registry → typed-error → event chain. Callers can't recover \
             on a specific failure mode."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Define a domain-specific error type (subclass / `thiserror::Error` enum) \
             and replace the generic raise."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}
