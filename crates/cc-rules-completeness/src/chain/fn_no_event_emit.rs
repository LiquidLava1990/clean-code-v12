//! `cc.chain.fn_no_event_emit` — fn whose name suggests state-change
//! (`save_*`, `update_*`, `delete_*`, `publish_*`) but whose body has
//! no event-emit Call.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_emit_callee, is_state_change_name, is_top_level_fn,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.chain.fn_no_event_emit`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FnNoEventEmitRule;

impl Rule for FnNoEventEmitRule {
    fn rule_id(&self) -> &'static str {
        "cc.chain.fn_no_event_emit"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "state-change fn does not emit an event"
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
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_state_change_name(name) {
        return None;
    }
    if fn_body_emits_event(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.chain.fn_no_event_emit",
        category: Category::Arch,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{name}` mutates state but emits no event"),
        explanation: "State-change functions that don't emit a typed event break the \
             observability chain — downstream consumers can't react to the change."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Emit a typed event after the mutation succeeds (e.g. `bus.emit(EntitySaved {...})`)."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

fn fn_body_emits_event(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    let mut stack = vec![fn_id];
    let mut budget = 4096_u16;
    while let Some(cur) = stack.pop() {
        if budget == 0 {
            return false;
        }
        budget -= 1;
        for child in ast_children(ctx.batch, cur) {
            if call_is_emit(ctx, child) {
                return true;
            }
            push_unless_nested_fn(ctx, child, &mut stack);
        }
    }
    false
}

/// True iff `child` is a `Call` whose callee name matches an emit pattern.
fn call_is_emit(ctx: &RuleContext<'_>, child: NodeId) -> bool {
    if node_kind(ctx.batch, child) != Some(NodeKind::Call) {
        return false;
    }
    let callee = string_prop(ctx.batch, child, "name").unwrap_or("");
    is_emit_callee(callee)
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
