//! `cc.meta.side_effect_undeclared` — function with apparent I/O calls
//! but no `#[side_effect]` / `@side_effect` decoration.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, has_decorator_containing, location_from_node,
    looks_like_io_call, CompletenessFindingBlueprint,
};

/// Probe `cc.meta.side_effect_undeclared`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SideEffectUndeclaredRule;

const SIDE_EFFECT_NEEDLES: &[&str] = &["side_effect", "side-effect", "effects"];

impl Rule for SideEffectUndeclaredRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.side_effect_undeclared"
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
        "fn contains I/O but is not annotated with a side-effect class"
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
    if !fn_has_io_call(ctx, id) {
        return None;
    }
    if has_decorator_containing(ctx.batch, id, SIDE_EFFECT_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.meta.side_effect_undeclared",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name}` performs I/O without a side-effect declaration"),
        explanation: "When the meta-registry can't see a function's side-effect class, \
             schedulers and retry policies can't reason about safety. Annotate the \
             effect (`db_read | db_write | net | fs`)."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `@side_effect(SideEffect.db_write)` / `#[side_effect(net)]` decorating \
             the function."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

/// Walk the function's AST_PARENT subtree and check every Call's
/// `name` against [`looks_like_io_call`].
fn fn_has_io_call(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    let mut stack = vec![fn_id];
    let mut budget = 4096_u16;
    while let Some(cur) = stack.pop() {
        if budget == 0 {
            return false;
        }
        budget -= 1;
        for child in ast_children(ctx.batch, cur) {
            if call_is_io(ctx, child) {
                return true;
            }
            push_unless_nested_fn(ctx, child, &mut stack);
        }
    }
    false
}

/// True iff `child` is a `Call` whose callee name looks like an I/O op.
fn call_is_io(ctx: &RuleContext<'_>, child: NodeId) -> bool {
    if node_kind(ctx.batch, child) != Some(NodeKind::Call) {
        return false;
    }
    let name = string_prop(ctx.batch, child, "name").unwrap_or("");
    looks_like_io_call(name)
}

/// Push `child` onto the traversal stack unless it opens a new function /
/// method scope (those are walked by their own owning rule iteration).
fn push_unless_nested_fn(ctx: &RuleContext<'_>, child: NodeId, stack: &mut Vec<NodeId>) {
    if matches!(
        node_kind(ctx.batch, child),
        Some(NodeKind::Function | NodeKind::Method)
    ) {
        return;
    }
    stack.push(child);
}

#[allow(dead_code)]
fn enclosing_function_check(ctx: &RuleContext<'_>, id: NodeId) -> Option<NodeId> {
    let mut cur = id;
    for _ in 0..256_u16 {
        cur = ast_parent(ctx.batch, cur)?;
        if matches!(
            node_kind(ctx.batch, cur),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            return Some(cur);
        }
    }
    None
}
