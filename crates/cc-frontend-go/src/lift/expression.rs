//! Lifters for expressions: calls, identifiers, literals, assignments.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::lift_node;
use crate::lift::parent_edge;
use crate::lift::types::{literal_kind_for, node_text};

/// Lift a `call_expression` into a [`NodeKind::Call`] node.
pub(crate) fn lift_call(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let callee_node = node.child_by_field_name("function");
    let callee_text = callee_node.map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let arg_count = node
        .child_by_field_name("arguments")
        .map_or(0u64, |n| n.named_child_count() as u64);
    let is_method_value = callee_node.is_some_and(is_method_value_callee);
    let is_dynamic = is_dynamic_call(&callee_text) || is_method_value;
    let builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", intern_string(store, &callee_text))
        .with_prop("arg_count", Value::Uint(arg_count))
        .with_prop("is_dynamic", Value::Bool(is_dynamic))
        .with_prop("is_method_value", Value::Bool(is_method_value))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let id = store.push_node(builder);
    lift_call_arguments(ctx, store, node, id);
    id
}

/// True when the callee expression is a method-value (selector that does
/// not itself end in a `call_expression`). This is the `is_method_value`
/// flag from `Function.lang_ext`, surfaced on the Call so dataflow knows
/// the dispatch is dynamic.
fn is_method_value_callee(callee: TsNode<'_>) -> bool {
    callee.kind() == "selector_expression"
}

/// Returns true for callees that perform runtime-dynamic dispatch.
fn is_dynamic_call(callee_text: &str) -> bool {
    const DYNAMIC: [&str; 3] = ["reflect.ValueOf", "reflect.Call", "unsafe.Pointer"];
    DYNAMIC.iter().any(|d| callee_text.starts_with(d))
}

/// Lift the named children of `call.arguments`.
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

/// Lift an `identifier` / `type_identifier` / `field_identifier` /
/// `package_identifier` into a [`NodeKind::Identifier`] node.
pub(crate) fn lift_identifier(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let name = node_text(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, name))
        .with_prop("ts_kind", intern_string(store, node.kind()))
        .with_prop("resolves_to", intern_string(store, "Unresolved"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift a literal token into a [`NodeKind::Literal`] node.
pub(crate) fn lift_literal(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let value_text = node_text(node, ctx.bytes());
    let kind_str = literal_kind_for(node);
    let builder = NodeBuilder::new(NodeKind::Literal)
        .with_prop("value", intern_string(store, value_text))
        .with_prop("literal_kind", intern_string(store, kind_str))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift an `assignment_statement` / `short_var_declaration` /
/// `var_declaration` / `const_declaration`.
///
/// Each assignment becomes a [`NodeKind::Write`] node. The RHS is
/// recursively lifted so reads inside it are recorded as `Read` /
/// `Identifier`. We additionally emit a [`NodeKind::Read`] sibling for the
/// RHS expression so dataflow can see the value being read into the
/// target.
pub(crate) fn lift_assignment(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let lhs_text = node.child_by_field_name("left").map_or_else(
        || extract_lhs_fallback(node, ctx.bytes()),
        |n| node_text(n, ctx.bytes()).to_owned(),
    );
    let op = node.child_by_field_name("operator").map_or_else(
        || infer_operator(node),
        |n| node_text(n, ctx.bytes()).to_owned(),
    );
    let write_id = build_write_node(store, node, &lhs_text, &op);

    if let Some(rhs) = node.child_by_field_name("right") {
        let read_id = build_read_node(store, rhs, ctx.bytes());
        parent_edge(store, read_id, write_id);
        if let Some(rhs_id) = lift_node(ctx, store, rhs, write_id) {
            parent_edge(store, rhs_id, write_id);
        }
    }
    write_id
}

/// Best-effort LHS extraction for declaration shapes that don't expose
/// the `left` field — `var_declaration` / `const_declaration` use a
/// `var_spec` child whose first identifier is the target name.
fn extract_lhs_fallback(node: TsNode<'_>, bytes: &[u8]) -> String {
    let mut cursor = node.walk();
    let spec = node
        .named_children(&mut cursor)
        .find(|c| matches!(c.kind(), "var_spec" | "const_spec"));
    spec.and_then(|s| first_identifier_text(s, bytes))
        .unwrap_or_default()
}

/// Return the text of the first `identifier` named child of `spec`, if any.
fn first_identifier_text(spec: TsNode<'_>, bytes: &[u8]) -> Option<String> {
    let mut cursor = spec.walk();
    let ident = spec
        .named_children(&mut cursor)
        .find(|c| c.kind() == "identifier");
    ident.map(|c| node_text(c, bytes).to_owned())
}

/// Map a tree-sitter node kind to its assignment operator text.
fn infer_operator(node: TsNode<'_>) -> String {
    match node.kind() {
        "short_var_declaration" => ":=".to_owned(),
        "var_declaration" => "var".to_owned(),
        "const_declaration" => "const".to_owned(),
        _ => "=".to_owned(),
    }
}

/// Build the `Write` node for an assignment.
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

/// Build a [`NodeKind::Read`] node carrying the RHS expression text.
fn build_read_node(store: &mut CpgWriteBatch, rhs: TsNode<'_>, bytes: &[u8]) -> NodeId {
    let text = node_text(rhs, bytes);
    let builder = NodeBuilder::new(NodeKind::Read)
        .with_prop("target", intern_string(store, text))
        .with_prop("range", Value::Range(range_from_ts_range(rhs.range())));
    store.push_node(builder)
}
