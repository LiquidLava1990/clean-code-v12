//! `cc.slop.defensive_pure_fn` — flag try/except wrapping a function
//! whose body has no I/O or side-effect calls.
//!
//! Heuristic: a function whose AST contains a [`NodeKind::Try`] child
//! BUT no [`NodeKind::Call`] children outside of the Try block (the
//! "pure" approximation in absence of side-effect props). This keeps
//! the false-positive rate low: real defensive code calls into IO or
//! database layers, which we'd see as Calls.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-DEFENSIVE.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefensivePureFnRule;

impl Rule for DefensivePureFnRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.defensive_pure_fn"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.88)
    }
    fn description(&self) -> &'static str {
        "try/except wraps a body with no I/O or side-effect calls"
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

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !has_try_descendant(ctx, id) {
        return None;
    }
    if has_call_descendant(ctx, id) {
        // At least one call exists -> we can't conclude purity from CPG
        // alone; skip rather than false-positive.
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.defensive_pure_fn",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.88),
        location,
        headline: format!("`{name}` wraps pure logic in try/except"),
        explanation: format!(
            "Function `{name}` contains a try/except block but its body \
             makes no calls — there is nothing to fail. Defensive wrappers \
             on pure logic obscure intent and swallow programmer errors."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Remove the try/except. If a specific failure mode is real, \
             write a typed precondition check at the call site instead."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

fn has_try_descendant(ctx: &RuleContext<'_>, root: NodeId) -> bool {
    walk_descendants(ctx, root, |child| {
        node_kind(ctx.batch, child) == Some(NodeKind::Try)
    })
}

fn has_call_descendant(ctx: &RuleContext<'_>, root: NodeId) -> bool {
    walk_descendants(ctx, root, |child| {
        node_kind(ctx.batch, child) == Some(NodeKind::Call)
    })
}

/// Bounded BFS over AST descendants, calling `pred` on each child. Bounds
/// the traversal at 4096 nodes to keep worst-case cost predictable.
fn walk_descendants(ctx: &RuleContext<'_>, root: NodeId, pred: impl Fn(NodeId) -> bool) -> bool {
    let mut frontier = vec![root];
    let mut visited: u32 = 0;
    while let Some(cur) = frontier.pop() {
        visited += 1;
        if visited > 4096 {
            return false;
        }
        for child in ast_children(ctx.batch, cur) {
            if pred(child) {
                return true;
            }
            frontier.push(child);
        }
    }
    false
}
