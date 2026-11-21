//! Lifters for expressions: calls, macros, identifiers, literals, await, and
//! let / assignment statements.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::lift_node;
use crate::lift::parent_edge;
use crate::lift::types::{literal_kind_for, node_text};

/// Lift `call_expression` / `method_call_expression` into a [`NodeKind::Call`].
pub(crate) fn lift_call(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let callee_text = callee_text_for(node, ctx.bytes());
    let arg_count = node
        .child_by_field_name("arguments")
        .map_or(0u64, |n| n.named_child_count() as u64);
    let is_dynamic = is_dynamic_call(&callee_text);
    let info = CallInfo {
        callee_text,
        arg_count,
        is_dynamic,
        is_macro: false,
    };
    let id = build_call_node(store, node, &info);
    lift_call_arguments(ctx, store, node, id);
    id
}

/// Lift a `macro_invocation` as a `Call` with `is_dynamic = true`.
///
/// Macros are syntactically unresolvable at the frontend layer (they expand
/// at compile time), so we mark them dynamic and record the macro path as
/// the callee reference for the call-graph builder to skip.
pub(crate) fn lift_macro(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let callee_text = node
        .child_by_field_name("macro")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let info = CallInfo {
        callee_text,
        arg_count: 0,
        is_dynamic: true,
        is_macro: true,
    };
    let id = build_call_node(store, node, &info);
    lift_macro_token_tree_args(ctx, store, node, id);
    id
}

/// Aggregate of the per-call CPG-node properties shared by `lift_call`
/// and `lift_macro`. Each variant only varies which fields it sets
/// (e.g. `is_macro` is always false for non-macro calls); a small struct
/// keeps the call-site readable and the builder in one place.
struct CallInfo {
    callee_text: String,
    arg_count: u64,
    is_dynamic: bool,
    is_macro: bool,
}

/// Build a [`NodeKind::Call`] CPG node from `info`. Shared between
/// `lift_call` (regular and method calls) and `lift_macro`. The
/// `is_macro` flag is only emitted when true so the regular-call shape
/// stays unchanged in the graph.
fn build_call_node(store: &mut CpgWriteBatch, node: TsNode<'_>, info: &CallInfo) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", intern_string(store, &info.callee_text))
        .with_prop("arg_count", Value::Uint(info.arg_count))
        .with_prop("is_dynamic", Value::Bool(info.is_dynamic))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    if info.is_macro {
        builder = builder.with_prop("is_macro", Value::Bool(true));
    }
    store.push_node(builder)
}

/// Lift the named arguments inside a macro's `token_tree` child as
/// children of the synthetic call node. Each token-tree wraps the
/// macro's brace / parenthesised body; named children inside it are the
/// expressions we surface in the graph.
fn lift_macro_token_tree_args(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    macro_node: TsNode<'_>,
    call_id: NodeId,
) {
    let mut cursor = macro_node.walk();
    for child in macro_node.named_children(&mut cursor) {
        if child.kind() == "token_tree" {
            lift_named_children_under(ctx, store, child, call_id);
        }
    }
}

/// Recursively lift each named child of `parent` as a child of
/// `parent_id`, wiring an `AST_PARENT` edge for every successful lift.
fn lift_named_children_under(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    parent: TsNode<'_>,
    parent_id: NodeId,
) {
    let mut cursor = parent.walk();
    for child in parent.named_children(&mut cursor) {
        if let Some(arg_id) = lift_node(ctx, store, child, parent_id) {
            parent_edge(store, arg_id, parent_id);
        }
    }
}

/// Borrow the callee expression text — `function` field for
/// `call_expression`, `method` (or `name`) field for method calls.
fn callee_text_for(node: TsNode<'_>, bytes: &[u8]) -> String {
    let f = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("method"))
        .or_else(|| node.child_by_field_name("name"));
    f.map_or(String::new(), |n| node_text(n, bytes).to_owned())
}

/// Returns true for callees that perform runtime-dynamic dispatch and so
/// can't be statically resolved.
fn is_dynamic_call(callee_text: &str) -> bool {
    // Trait-object dispatch and dyn fn pointers can't be resolved by the
    // call-graph builder. We treat any path starting with `dyn ` or
    // containing the canonical `Box<dyn` / `&dyn` markers as dynamic.
    callee_text.starts_with("dyn ") || callee_text.contains("dyn ")
}

/// Lift the named children of a call's `arguments` node so each argument
/// appears in the graph beneath the `Call`.
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

/// Lift an `identifier` / `field_identifier` / `type_identifier` into a
/// [`NodeKind::Identifier`] node — `resolves_to` starts as `Unresolved` and
/// is filled in by the post-pass resolver.
pub(crate) fn lift_identifier(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let name = node_text(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, name))
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

/// Lift `expr.await` into an [`NodeKind::Async`] wrapper containing the
/// awaited expression as a child.
pub(crate) fn lift_await(
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

/// Lift a `let_declaration` — the bound pattern becomes a [`NodeKind::Write`]
/// (the binding site) and the initializer is recursively lifted as the RHS.
pub(crate) fn lift_let(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    lift_binding(
        ctx,
        store,
        node,
        BindingFields {
            lhs: "pattern",
            rhs: "value",
            op_field: None,
            default_op: "=",
        },
    )
}

/// Lift `assignment_expression` / `compound_assignment_expr` into a `Write`
/// node carrying the target text + assignment operator. The RHS is
/// recursively lifted so reads inside it appear as `Read` / `Identifier`.
pub(crate) fn lift_assignment(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    lift_binding(
        ctx,
        store,
        node,
        BindingFields {
            lhs: "left",
            rhs: "right",
            op_field: Some("operator"),
            default_op: "=",
        },
    )
}

/// Names of the LHS / RHS / operator child fields on a binding-shape
/// tree-sitter node. `let_declaration` uses `pattern` / `value` and a
/// fixed `=` operator; `assignment_expression` uses `left` / `right`
/// and reads the operator from the `operator` child. The struct keeps
/// these knobs in one place so the lifter body is identical for both.
#[derive(Debug, Clone, Copy)]
struct BindingFields {
    lhs: &'static str,
    rhs: &'static str,
    op_field: Option<&'static str>,
    default_op: &'static str,
}

/// Shared body for `lift_let` and `lift_assignment`. Reads the LHS
/// text, resolves the operator (literal or field-driven), pushes a
/// `Write` node, then recursively lifts the RHS as a child with an
/// `AST_PARENT` edge.
fn lift_binding(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    fields: BindingFields,
) -> NodeId {
    let lhs_text = node
        .child_by_field_name(fields.lhs)
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let op = fields.op_field.map_or(fields.default_op, |field| {
        node.child_by_field_name(field)
            .map_or(fields.default_op, |n| node_text(n, ctx.bytes()))
    });
    let write_id = build_write_node(store, node, &lhs_text, op);
    if let Some(rhs) = node.child_by_field_name(fields.rhs) {
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
