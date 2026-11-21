//! `cc.observe.public_fn_untraced` — a public, top-level function that
//! does not carry one of the canonical tracing decorators.
//!
//! Heuristic (Phase 2): a top-level `pub` function with NO decorator
//! whose name matches the canonical tracing patterns
//! (`tracing::instrument`, `instrument`, `trace_async`, `meta_async`,
//! `span`, `traced`).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, has_decorator_containing, is_public_fn, is_top_level_fn,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.observe.public_fn_untraced`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicFnUntracedRule;

const TRACE_DECORATOR_NEEDLES: &[&str] = &[
    "instrument",
    "trace_async",
    "meta_async",
    "traced",
    "span",
    "tracing",
];

impl Rule for PublicFnUntracedRule {
    fn rule_id(&self) -> &'static str {
        "cc.observe.public_fn_untraced"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "public, top-level function lacks a tracing/instrumentation decorator"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Function) {
            if let Some(f) = check_fn(ctx, node.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    if !is_public_fn(ctx.batch, id) {
        return None;
    }
    if has_decorator_containing(ctx.batch, id, TRACE_DECORATOR_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.observe.public_fn_untraced",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("public fn `{name}` is not instrumented"),
        explanation: "Public entry points without tracing decoration are blind in production. \
             Add `#[tracing::instrument]`, `@trace_async`, or the project's canonical \
             span decorator so the function shows up in distributed traces."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `#[tracing::instrument]` (Rust) / `@trace_async` (Python) above the \
             function declaration."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}
