//! `cc.shape.nesting_early_return` — flag depth-1 `Branch` nodes whose
//! true-arm contains another `Branch`. Such nests are usually
//! candidates for guard-clause refactoring (invert + early return).
//!
//! Phase-1 simplification: full guard-clause analysis (else-arm exits,
//! single statement after) needs CFG + return-statement classification
//! we do not yet have. Flagging "nested Branch directly inside an
//! outer Branch at function depth 1" catches the canonical anti-pattern
//! without false positives on simple `if`/`else if` chains.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Tier-0 forever rule R-NEST-EARLY.
#[derive(Debug, Default, Clone, Copy)]
pub struct NestingEarlyReturnRule;

impl Rule for NestingEarlyReturnRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.nesting_early_return"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "branch nests another branch — invert and use an early return"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for fn_node in nodes_of_kind(ctx.batch, kind) {
                collect_for_function(ctx, fn_node.id, &mut out);
            }
        }
        out
    }
}

fn collect_for_function(ctx: &RuleContext<'_>, fn_id: NodeId, out: &mut Vec<Finding>) {
    for child in ast_children(ctx.batch, fn_id) {
        if node_kind(ctx.batch, child) != Some(NodeKind::Branch) {
            continue;
        }
        if !has_branch_descendant(ctx, child) {
            continue;
        }
        if let Some(finding) = build_early_return_finding(ctx, fn_id, child) {
            out.push(finding);
        }
    }
}

fn build_early_return_finding(
    ctx: &RuleContext<'_>,
    fn_id: NodeId,
    branch_id: NodeId,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, branch_id)?;
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, branch_id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.nesting_early_return",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("function `{name}` nests a branch — invert and return early"),
        explanation: format!(
            "Function `{name}` opens a top-level branch that wraps another \
             branch. Invert the outer condition, return early, and keep the \
             happy path at indent 1."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `if cond:` { … } with `if !cond: return …` and unindent the \
             remaining body. Guard clauses keep nesting flat."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}

fn has_branch_descendant(ctx: &RuleContext<'_>, root: NodeId) -> bool {
    for child in ast_children(ctx.batch, root) {
        if node_kind(ctx.batch, child) == Some(NodeKind::Branch) {
            return true;
        }
        if has_branch_descendant(ctx, child) {
            return true;
        }
    }
    false
}
