//! Lifters for expressions: calls, identifiers, literals, await, and
//! assignments.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{literal_kind_for, node_text};
use crate::lift::{lift_node, parent_edge};

/// Try to handle `node` as an expression-shaped construct.
pub(crate) fn dispatch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "call_expression" | "new_expression" => Some(lift_call(ctx, store, node, parent)),
        "identifier"
        | "type_identifier"
        | "property_identifier"
        | "shorthand_property_identifier" => Some(lift_identifier(ctx, store, node)),
        "string" | "number" | "true" | "false" | "null" | "undefined" | "template_string"
        | "regex" => Some(lift_literal(ctx, store, node)),
        "await_expression" => Some(lift_await(ctx, store, node, parent)),
        "assignment_expression" | "augmented_assignment_expression" => {
            Some(lift_assignment(ctx, store, node, parent))
        }
        _ => None,
    }
}

/// Lift a `call_expression` / `new_expression` into a [`NodeKind::Call`] node.
fn lift_call(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let callee_text = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("constructor"))
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let arg_count = node
        .child_by_field_name("arguments")
        .map_or(0u64, |n| n.named_child_count() as u64);
    let is_dynamic = is_dynamic_call(&callee_text);
    let is_new = node.kind() == "new_expression";
    let builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", intern_string(store, &callee_text))
        .with_prop("arg_count", Value::Uint(arg_count))
        .with_prop("is_dynamic", Value::Bool(is_dynamic))
        .with_prop("is_new", Value::Bool(is_new))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let id = store.push_node(builder);
    lift_call_arguments(ctx, store, node, id);
    id
}

/// Returns true for callees that perform runtime-dynamic dispatch and so
/// can't be statically resolved by the call-graph builder.
fn is_dynamic_call(callee_text: &str) -> bool {
    const DYNAMIC: [&str; 6] = [
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "Reflect.apply",
        "Reflect.construct",
    ];
    DYNAMIC.iter().any(|d| *d == callee_text)
}

/// Lift the named children of a call's `arguments` node so each argument
/// expression appears in the graph beneath the `Call`.
fn lift_call_arguments(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    call: TsNode<'_>,
    call_id: NodeId,
) {
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if let Some(arg_id) = lift_node(ctx, store, arg, call_id) {
            parent_edge(store, arg_id, call_id);
        }
    }
}

/// Lift an `identifier` into a [`NodeKind::Identifier`] node. `resolves_to`
/// starts as `Unresolved` and is filled in by the post-pass resolver.
fn lift_identifier(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let name = node_text(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, name))
        .with_prop("resolves_to", intern_string(store, "Unresolved"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift a literal token into a [`NodeKind::Literal`] node. The
/// `literal_kind` property carries the discriminator (`str` / `num` /
/// `bool` / `null` / `undefined` / `template` / `regex`).
fn lift_literal(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let value_text = node_text(node, ctx.bytes());
    let kind_str = literal_kind_for(node);
    let builder = NodeBuilder::new(NodeKind::Literal)
        .with_prop("value", intern_string(store, value_text))
        .with_prop("literal_kind", intern_string(store, kind_str))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift `await expr` into an [`NodeKind::Async`] wrapper containing the
/// awaited expression as a child.
fn lift_await(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Async)
        .with_prop("async_kind", intern_string(store, "await"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let id = store.push_node(builder);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(child_id) = lift_node(ctx, store, child, id) {
            parent_edge(store, child_id, id);
        }
    }
    id
}

/// Lift an `assignment_expression` / `augmented_assignment_expression`.
///
/// The target becomes a [`NodeKind::Write`]; the RHS is recursively
/// lifted so reads inside it are recorded as `Read` / `Identifier`.
fn lift_assignment(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let lhs_text = node
        .child_by_field_name("left")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let op = node
        .child_by_field_name("operator")
        .map_or("=", |n| node_text(n, ctx.bytes()));
    let write_id = build_write_node(store, node, &lhs_text, op);
    if let Some(left) = node.child_by_field_name("left") {
        if let Some(read_id) = lift_node(ctx, store, left, write_id) {
            parent_edge(store, read_id, write_id);
        }
    }
    if let Some(rhs) = node.child_by_field_name("right") {
        if let Some(rhs_id) = lift_node(ctx, store, rhs, write_id) {
            parent_edge(store, rhs_id, write_id);
        }
    }
    write_id
}

/// Build the `Write` node carrying the target name + assignment operator.
fn build_write_node(
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    lhs_text: &str,
    op: &str,
) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Write)
        .with_prop("target", intern_string(store, lhs_text))
        .with_prop("operator", intern_string(store, op))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}
