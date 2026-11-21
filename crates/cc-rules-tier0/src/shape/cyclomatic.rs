//! `cc.shape.cyclomatic` — McCabe complexity > 10.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Phase-1 default threshold per `docs/design/TIER_0_ALGORITHMS.md`.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_CYC: u32 = 10;

/// Tier-0 forever rule R-CYC.
#[derive(Debug, Default, Clone, Copy)]
pub struct CyclomaticRule;

impl Rule for CyclomaticRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.cyclomatic"
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
        "function McCabe cyclomatic complexity exceeds threshold (default 10)"
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
    let cc = cyclomatic(ctx.batch, id);
    if cc <= DEFAULT_MAX_CYC {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = (cc - DEFAULT_MAX_CYC).saturating_mul(2);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.cyclomatic",
        category: Category::Shape,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: format!(
            "function `{name}` cyclomatic complexity is {cc} (threshold {DEFAULT_MAX_CYC})"
        ),
        explanation: format!(
            "High cyclomatic complexity multiplies test paths. `{name}` reaches {cc}; \
             the Tier-0 ceiling is {DEFAULT_MAX_CYC}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract branches into helpers; replace nested conditionals with early returns.".into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// McCabe — count of branches + 1. We count `Branch` and `Loop` AST
/// descendants and add one for the implicit straight-line path.
fn cyclomatic(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    let branches = count_branches(batch, root);
    branches.saturating_add(1)
}

fn count_branches(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    let mut count: u32 = 0;
    for child in ast_children(batch, root) {
        if matches!(
            node_kind(batch, child),
            Some(NodeKind::Branch | NodeKind::Loop)
        ) {
            count = count.saturating_add(1);
        }
        count = count.saturating_add(count_branches(batch, child));
    }
    count
}
