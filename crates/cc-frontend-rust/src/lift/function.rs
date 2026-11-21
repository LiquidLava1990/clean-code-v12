//! Lifters for `function_item`, `impl_item`, and the class-shaped items
//! (`struct_item` / `enum_item` / `trait_item` / `union_item`).

use std::collections::BTreeMap;

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use cc_frontend::visibility::{rust_visibility, Visibility};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{
    class_kind_for, declared_lifetimes, function_signature, impl_self_type, is_async_function,
    is_const_function, is_unsafe_function, node_text, visibility_modifier_text, where_clauses,
};
use crate::lift::{declares_edge, lift_children_into, parent_edge};

/// Lift a `function_item` (or `function_signature_item` from a trait body).
///
/// Decides between [`NodeKind::Function`] and [`NodeKind::Method`] using the
/// surrounding [`LiftCtx::inside_impl`] flag.
pub(crate) fn lift_function(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let attrs = FunctionAttrs::from_node(node, ctx);
    let kind = if ctx.inside_impl() {
        NodeKind::Method
    } else {
        NodeKind::Function
    };
    let lang_ext = build_lang_ext(&attrs, ctx);
    let id = build_function_node(store, node, kind, &attrs, lang_ext);
    if !ctx.inside_impl() {
        declares_edge(store, parent, id);
    }
    if let Some(p) = node.child_by_field_name("parameters") {
        lift_parameters(ctx, store, p, id);
    }
    if let Some(b) = node.child_by_field_name("body") {
        if let Some(body_id) = super::lift_node(ctx, store, b, id) {
            parent_edge(store, body_id, id);
        }
    }
    id
}

/// Cluster of source-derived attributes used to populate the function node
/// without forcing the builder call into a god function.
struct FunctionAttrs {
    name: String,
    signature: String,
    is_async: bool,
    is_unsafe: bool,
    is_const: bool,
    lifetimes: Vec<String>,
    where_clauses: Vec<String>,
    visibility: Visibility,
}

impl FunctionAttrs {
    fn from_node(node: TsNode<'_>, ctx: &LiftCtx<'_>) -> Self {
        let visibility = rust_visibility(visibility_modifier_text(node, ctx.bytes()));
        Self {
            name: node
                .child_by_field_name("name")
                .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned()),
            signature: function_signature(node, ctx.bytes()),
            is_async: is_async_function(node, ctx.bytes()),
            is_unsafe: is_unsafe_function(node, ctx.bytes()),
            is_const: is_const_function(node, ctx.bytes()),
            lifetimes: declared_lifetimes(node, ctx.bytes()),
            where_clauses: where_clauses(node, ctx.bytes()),
            visibility,
        }
    }
}

/// Construct the `Function` / `Method` node carrying the canonical schema
/// props plus the Rust `lang_ext` map.
fn build_function_node(
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    kind: NodeKind,
    attrs: &FunctionAttrs,
    lang_ext: BTreeMap<String, Value>,
) -> NodeId {
    let builder = NodeBuilder::new(kind)
        .with_prop("name", intern_string(store, &attrs.name))
        .with_prop("signature", intern_string(store, &attrs.signature))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop(
            "line_start",
            Value::Uint((node.start_position().row + 1) as u64),
        )
        .with_prop(
            "line_end",
            Value::Uint((node.end_position().row + 1) as u64),
        )
        .with_prop("is_async", Value::Bool(attrs.is_async))
        .with_prop("lang_ext", Value::Map(lang_ext));
    let builder = attrs.visibility.stamp(builder);
    store.push_node(builder)
}

/// Build the `lang_ext` map for a function — captures the four Rust-specific
/// extras (`is_unsafe`, `lifetimes`, `where_clauses`, `is_const_fn`) plus the
/// receiver type when we're inside an `impl` block.
fn build_lang_ext(attrs: &FunctionAttrs, ctx: &LiftCtx<'_>) -> BTreeMap<String, Value> {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("is_unsafe".to_owned(), Value::Bool(attrs.is_unsafe));
    map.insert("is_const_fn".to_owned(), Value::Bool(attrs.is_const));
    map.insert("is_async".to_owned(), Value::Bool(attrs.is_async));
    map.insert(
        "lifetimes".to_owned(),
        Value::String(attrs.lifetimes.join(",")),
    );
    map.insert(
        "where_clauses".to_owned(),
        Value::String(attrs.where_clauses.join(";")),
    );
    if ctx.inside_impl() && !ctx.receiver_type.is_empty() {
        map.insert(
            "receiver_type".to_owned(),
            Value::String(ctx.receiver_type.clone()),
        );
    }
    map
}

/// Lift an `impl_item` — emits no node of its own; instead it sets the
/// `inside_impl` flag + receiver type so any `function_item` children become
/// methods, then walks the body.
///
/// To preserve the AST shape we still build a [`NodeKind::Block`] anchor for
/// the impl, parented under the module — this gives `DECLARES` edges a
/// concrete target and keeps the impl visible in the graph.
pub(crate) fn lift_impl(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let receiver = impl_self_type(node, ctx.bytes());
    let trait_text = node
        .child_by_field_name("trait")
        .map(|n| node_text(n, ctx.bytes()).to_owned())
        .unwrap_or_default();
    let builder = NodeBuilder::new(NodeKind::Block)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("impl_self_type", intern_string(store, &receiver))
        .with_prop("impl_trait", intern_string(store, &trait_text));
    let id = store.push_node(builder);
    let prev_receiver = std::mem::replace(&mut ctx.receiver_type, receiver);
    ctx.impl_depth += 1;
    if let Some(body) = node.child_by_field_name("body") {
        lift_children_into(ctx, store, body, id);
    }
    ctx.impl_depth -= 1;
    ctx.receiver_type = prev_receiver;
    id
}

/// Lift one of the four class-shaped item kinds.
pub(crate) fn lift_class(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let name = node
        .child_by_field_name("name")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let kind_label = class_kind_for(node.kind());
    let visibility = rust_visibility(visibility_modifier_text(node, ctx.bytes()));
    let builder = NodeBuilder::new(NodeKind::Class)
        .with_prop("name", intern_string(store, &name))
        .with_prop("kind", intern_string(store, kind_label))
        .with_prop("superclasses", intern_string(store, ""))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let builder = visibility.stamp(builder);
    let id = store.push_node(builder);
    declares_edge(store, parent, id);
    if let Some(body) = node.child_by_field_name("body") {
        lift_children_into(ctx, store, body, id);
    }
    id
}

/// Lift the `parameters` child of a `function_item` into a sequence of
/// [`NodeKind::Parameter`] nodes, preserving positional order.
fn lift_parameters(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    params: TsNode<'_>,
    function_id: NodeId,
) {
    let mut cursor = params.walk();
    for (idx, child) in params.named_children(&mut cursor).enumerate() {
        let id = build_parameter(ctx, store, child, idx);
        parent_edge(store, id, function_id);
    }
}

/// Build a single [`NodeKind::Parameter`] node from a parameter child.
///
/// Handles `parameter` (typed), `self_parameter`, and `variadic_parameter`.
/// `is_self` is inferred from the `self_parameter` kind.
fn build_parameter(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    position: usize,
) -> NodeId {
    let (name, ty) = parameter_name_and_type(node, ctx.bytes());
    let is_self = node.kind() == "self_parameter";
    let builder = NodeBuilder::new(NodeKind::Parameter)
        .with_prop("name", intern_string(store, &name))
        .with_prop("type", intern_string(store, &ty))
        .with_prop("default", intern_string(store, ""))
        .with_prop("is_self", Value::Bool(is_self))
        .with_prop("position", Value::Uint(position as u64))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Extract `(name, type_text)` from a parameter child.
///
/// `parameter` exposes `pattern` (lhs) + `type` (rhs); `self_parameter`
/// surfaces as `self` directly. We fall back to the node's own text when
/// neither field is present (variadic / unusual shapes).
fn parameter_name_and_type(node: TsNode<'_>, bytes: &[u8]) -> (String, String) {
    if node.kind() == "self_parameter" {
        return ("self".to_owned(), String::new());
    }
    let name = node.child_by_field_name("pattern").map_or_else(
        || node_text(node, bytes).to_owned(),
        |n| node_text(n, bytes).to_owned(),
    );
    let ty = node
        .child_by_field_name("type")
        .map_or(String::new(), |n| node_text(n, bytes).to_owned());
    (name, ty)
}
