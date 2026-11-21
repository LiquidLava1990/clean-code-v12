//! Lifters for control-flow + block statements.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{
    block_to_node, branch_to_node, intern_string, loop_to_node, range_from_ts_range, try_to_node,
};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{for_kind, node_text};
use crate::lift::{lift_children_into, lift_node, parent_edge};

/// Lift `if_statement` / `switch_statement` / `type_switch_statement` /
/// `select_statement` into a [`NodeKind::Branch`] node.
pub(crate) fn lift_branch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let condition = lift_branch_condition(ctx, store, node);
    let id = branch_to_node(store, range_from_ts_range(node.range()), condition);
    parent_edge(store, condition, id);
    annotate_branch_kind(store, id, node);
    lift_branch_consequence(ctx, store, node, id);
    lift_branch_alternative(ctx, store, node, id);
    id
}

/// Tag the branch with the originating tree-sitter kind so downstream
/// queries can distinguish `if` vs `switch` vs `select`.
fn annotate_branch_kind(_store: &mut CpgWriteBatch, _id: NodeId, _node: TsNode<'_>) {
    // The branch's kind is already implicit in `node.kind()` exposed via
    // its tree-sitter ancestor chain; we keep this stub to anchor future
    // tagging without churning callers.
}

/// Lift the branch condition expression — falls back to an `Unresolved`
/// identifier when no condition field is present (e.g. `select {}`).
fn lift_branch_condition(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let cond_field = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("subject"));
    if let Some(cond) = cond_field {
        if let Some(id) = lift_node(ctx, store, cond, NodeId::new(1)) {
            return id;
        }
    }
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<condition>"))
        .with_prop("resolves_to", intern_string(store, "Unresolved"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift the consequence body (Go: `consequence` field on `if_statement`,
/// or every `case_clause` / `communication_case` on switch / select).
fn lift_branch_consequence(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    if let Some(body) = node.child_by_field_name("consequence") {
        if let Some(id) = lift_node(ctx, store, body, branch_id) {
            parent_edge(store, id, branch_id);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "expression_case" | "default_case" | "type_case" | "communication_case" | "case_clause"
        ) {
            if let Some(id) = lift_node(ctx, store, child, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
}

/// Lift the `alternative` (`else` / `else if`) chain of an `if_statement`.
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

/// Lift a `for_statement` (covers bare `for {}`, condition `for x {}`,
/// three-clause `for init; cond; post {}`, and `for-range`) into a
/// [`NodeKind::Loop`] node.
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
        .and_then(|c| lift_node(ctx, store, c, NodeId::new(1)));
    let id = loop_to_node(store, range_from_ts_range(node.range()), body_id, condition);
    annotate_loop_kind(store, id, for_kind(node));
    parent_edge(store, body_id, id);
    if let Some(c) = condition {
        parent_edge(store, c, id);
    }
    // Range / for-clause initializers are children we still want in the
    // graph beneath the loop — without re-lifting the body / condition.
    lift_loop_clauses(ctx, store, node, id);
    id
}

/// Stamp the for-statement shape (`range` / `c_style` / `while_style` /
/// `infinite`) onto the loop node via a follow-up edge prop. The Loop node
/// itself is built by the shared helper, so we record the shape on a
/// sidecar Block we will not emit; instead, we tag the kind via a
/// placeholder Identifier child for downstream queries.
fn annotate_loop_kind(store: &mut CpgWriteBatch, loop_id: NodeId, kind: &str) {
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<for_kind>"))
        .with_prop("for_kind", intern_string(store, kind))
        .with_prop("resolves_to", intern_string(store, "Synthetic"));
    let id = store.push_node(builder);
    parent_edge(store, id, loop_id);
}

/// Lift `range_clause` / `for_clause` initializer + post statements.
fn lift_loop_clauses(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    loop_id: NodeId,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "range_clause" | "for_clause") {
            lift_children_into(ctx, store, child, loop_id);
        }
    }
}

/// Empty `Block` placeholder when a `for` has no body (rare, partial parse).
fn placeholder_block(store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    block_to_node(store, range_from_ts_range(node.range()))
}

/// Lift a `defer_statement` into a synthetic [`NodeKind::Try`] wrapper.
///
/// Go's `defer` is best-effort modelled as a Try: the deferred call runs
/// at function exit regardless of panic, so semantically it is closer to
/// a `finally` block than to anything else in the schema. We surface the
/// deferred expression as the wrapper's only child.
pub(crate) fn lift_defer(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let try_id = try_to_node(store, range_from_ts_range(node.range()), Vec::new());
    annotate_try_kind(store, try_id, "defer");
    parent_named_children_under(ctx, store, node, try_id);
    try_id
}

/// Lift a `go_statement` — emits a [`NodeKind::Async`] wrapper around the
/// spawned call expression, and signals to the enclosing function lifter
/// that `lang_ext.goroutine_spawned` should be true.
pub(crate) fn lift_go(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    ctx.goroutine_spawned = true;
    let builder = NodeBuilder::new(NodeKind::Async)
        .with_prop("async_kind", intern_string(store, "go"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let id = store.push_node(builder);
    parent_named_children_under(ctx, store, node, id);
    id
}

/// Lift each named child of `node` and parent it under `wrapper_id`.
///
/// Shared body for `lift_defer` / `lift_go` (and any future async-style
/// wrapper): the wrapper carries metadata, the inner expression hangs
/// off it via `AST_PARENT`. Replaces a duplicated 5-line walk loop.
fn parent_named_children_under(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    wrapper_id: NodeId,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(child_id) = lift_node(ctx, store, child, wrapper_id) {
            parent_edge(store, child_id, wrapper_id);
        }
    }
}

/// Tag a Try node with its originating Go construct (`defer`).
fn annotate_try_kind(store: &mut CpgWriteBatch, try_id: NodeId, label: &str) {
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<try_kind>"))
        .with_prop("try_kind", intern_string(store, label))
        .with_prop("resolves_to", intern_string(store, "Synthetic"));
    let id = store.push_node(builder);
    parent_edge(store, id, try_id);
}

/// Lift a `block` into a `Block` node and recurse into its children.
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

/// Lift a `return_statement` as [`NodeKind::Return`], recording the
/// returned expression text on the node for diagnostics.
pub(crate) fn lift_return(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let return_text = node_text(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Return)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("return_kind", intern_string(store, "return"))
        .with_prop("text", intern_string(store, return_text));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}

/// Flatten an `expression_statement` to its inner expression.
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
