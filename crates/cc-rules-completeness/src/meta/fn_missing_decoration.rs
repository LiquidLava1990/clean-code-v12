//! `cc.meta.fn_missing_decoration` — top-level public function lacking
//! the project's canonical metadata decorator.
//!
//! Phase-2 heuristic: hardcoded canonical patterns
//! (`#[tracing::instrument]`, `@trace_async`, `@meta_async`,
//! `@instrument`, `@traced`). The full per-project `decorator_norm`
//! field on `Fingerprint` lands in Phase 3.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, has_decorator_containing, is_public_fn, is_top_level_fn,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.meta.fn_missing_decoration`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FnMissingDecorationRule;

const META_DECORATOR_NEEDLES: &[&str] = &[
    "trace_async",
    "meta_async",
    "instrument",
    "traced",
    "meta(",
    "register_fn",
];

impl Rule for FnMissingDecorationRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.fn_missing_decoration"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "public, top-level fn lacks the project's metadata decorator"
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
    if has_decorator_containing(ctx.batch, id, META_DECORATOR_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.meta.fn_missing_decoration",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{name}` is not registered in the meta-registry"),
        explanation: "Functions outside the meta-registry can't carry side-effect / \
             timing / schema metadata. Add the project's canonical decorator so the \
             registry tracks owner, input/output schema, and resource envelope."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `@meta_async` / `@trace_async` (Python) or `#[tracing::instrument]` \
             (Rust) above the function."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}
