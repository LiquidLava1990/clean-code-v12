//! Lifters for control-flow + block statements.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{
    block_to_node, branch_to_node, intern_string, loop_to_node, range_from_ts_range, try_to_node,
};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::{lift_children_into, lift_node, parent_edge};

/// Lift `if_expression` / `match_expression` into a `Branch` node.
pub(crate) fn lift_branch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let condition = lift_branch_condition(ctx, store, node);
    let id = branch_to_node(store, range_from_ts_range(node.range()), condition);
    parent_edge(store, condition, id);
    lift_branch_consequence(ctx, store, node, id);
    lift_branch_alternative(ctx, store, node, id);
    id
}

/// Lift the `condition` (if) / `value` (match) field, falling back to a
/// synthetic `Unresolved` marker when neither is present.
fn lift_branch_condition(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let cond_field = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("value"));
    if let Some(cond) = cond_field {
        if let Some(id) = lift_node(ctx, store, cond, NodeId::new(1)) {
            return id;
        }
    }
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<condition>"))
        .with_prop("resolves_to", intern_string(store, "Unresolved"));
    store.push_node(builder)
}

/// Lift the `consequence` / `body` body of a branch, plus any `match_arm`
/// children for `match_expression`.
fn lift_branch_consequence(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    if let Some(body) = node
        .child_by_field_name("consequence")
        .or_else(|| node.child_by_field_name("body"))
    {
        if let Some(id) = lift_node(ctx, store, body, branch_id) {
            parent_edge(store, id, branch_id);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "match_arm" || child.kind() == "match_block" {
            if let Some(id) = lift_node(ctx, store, child, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
}

/// Lift the `alternative` arm of an `if_expression` (else / else-if).
fn lift_branch_alternative(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    if let Some(alt) = node.child_by_field_name("alternative") {
        if let Some(id) = lift_node(ctx, store, alt, branch_id) {
            parent_edge(store, id, branch_id);
        }
    }
}

/// Lift `for_expression` / `while_expression` / `loop_expression` into a
/// `Loop` node.
pub(crate) fn lift_loop(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let body_id = node
        .child_by_field_name("body")
        .and_then(|b| lift_node(ctx, store, b, NodeId::new(1)))
        .unwrap_or_else(|| placeholder_block(store, node));
    let condition = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("value"))
        .and_then(|c| lift_node(ctx, store, c, NodeId::new(1)));
    let id = loop_to_node(store, range_from_ts_range(node.range()), body_id, condition);
    parent_edge(store, body_id, id);
    if let Some(c) = condition {
        parent_edge(store, c, id);
    }
    id
}

/// Build an empty `Block` placeholder when a control-flow node has no body.
fn placeholder_block(store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    block_to_node(store, range_from_ts_range(node.range()))
}

/// Lift a `try_expression` (the `?` operator) or `try_block` into a `Try`
/// node. Rust's `?` is a expression-level operator, so we treat it as a
/// minimal `Try` with the inner expression as the "body" and no explicit
/// catch handlers — the implicit propagation is recorded as the operator.
pub(crate) fn lift_try(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let try_id = try_to_node(store, range_from_ts_range(node.range()), Vec::new());
    lift_children_into(ctx, store, node, try_id);
    try_id
}

/// Lift a `block` / `block_expression` into a `Block` node and recurse into
/// its children.
pub(crate) fn lift_block(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let id = block_to_node(store, range_from_ts_range(node.range()));
    lift_children_into(ctx, store, node, id);
    id
}

/// Lift `return_expression` as `Return`.
pub(crate) fn lift_return(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Return)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("return_kind", intern_string(store, "return"));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}

/// Lift an `expression_statement` — flattens to its (single) inner
/// expression so we don't double-nest the AST.
pub(crate) fn lift_expression_statement(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next()?;
    lift_node(ctx, store, first, parent)
}
