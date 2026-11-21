//! `cc.shape.param_count` — flag functions with > 5 positional parameters.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, bool_prop, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Phase-1 default threshold per `docs/design/TIER_0_ALGORITHMS.md`.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_PARAMS: u32 = 5;

/// Tier-0 forever rule R-PARAMS.
#[derive(Debug, Default, Clone, Copy)]
pub struct ParamCountRule;

impl Rule for ParamCountRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.param_count"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "function has more than 5 positional parameters"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_function(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let positional = count_positional_params(ctx, id);
    if positional <= DEFAULT_MAX_PARAMS {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.param_count",
        category: Category::Shape,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: format!(
            "function `{name}` takes {positional} positional params (threshold {DEFAULT_MAX_PARAMS})"
        ),
        explanation: format!(
            "Long parameter lists hide a missing data type. `{name}` accepts \
             {positional} positional parameters; the Tier-0 ceiling is {DEFAULT_MAX_PARAMS}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Group related parameters into a struct / dataclass; use keyword-only for opt-ins."
                .into(),
        ),
        snippet: String::new(),
        weight: positional - DEFAULT_MAX_PARAMS,
    }))
}

fn count_positional_params(ctx: &RuleContext<'_>, fn_id: NodeId) -> u32 {
    let mut count: u32 = 0;
    for child in ast_children(ctx.batch, fn_id) {
        if node_kind(ctx.batch, child) != Some(NodeKind::Parameter) {
            continue;
        }
        if is_positional(ctx, child) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn is_positional(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if bool_prop(ctx.batch, id, "is_keyword_only").unwrap_or(false) {
        return false;
    }
    if bool_prop(ctx.batch, id, "is_self").unwrap_or(false) {
        return false;
    }
    if bool_prop(ctx.batch, id, "is_rest").unwrap_or(false) {
        return false;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("");
    !matches!(name, "self" | "this" | "cls")
}
