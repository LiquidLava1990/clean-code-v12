//! `cc.contract.precondition_missing` — function with `unsafe` /
//! numeric-arg / array-index logic but no entry-time guard.
//!
//! Heuristic: function body contains an `unsafe { }` block OR an
//! indexed access (`[`) AND has zero `assert!`/`assert`/`if` early
//! return at function start.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_body_text, is_top_level_fn, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.contract.precondition_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PreconditionMissingRule;

const RISKY_NEEDLES: &[&str] = &["unsafe {", "unsafe{", "[index", "as_ptr", "from_raw"];
const GUARD_NEEDLES: &[&str] = &[
    "assert!",
    "assert(",
    "debug_assert",
    "precondition",
    "ensure!",
];

impl Rule for PreconditionMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.contract.precondition_missing"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "fn has risky access patterns but no precondition guard"
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
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source)?;
    if !RISKY_NEEDLES.iter().any(|n| body.contains(n)) {
        return None;
    }
    if GUARD_NEEDLES.iter().any(|n| body.contains(n)) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.contract.precondition_missing",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{name}` performs risky operations without a precondition"),
        explanation: "Functions touching `unsafe` / raw indices / pointer casts must \
             validate inputs at entry. Without a guard, invalid inputs cause UB or \
             panics deep in the call tree."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `assert!(...)` / `debug_assert!(...)` / `if !valid { return Err(...) }` \
             at the top of the function."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 2,
    }))
}
