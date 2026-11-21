//! Lifters for `function_definition`, `class_definition`, and the
//! tree-sitter-python `decorated_definition` wrapper that hangs decorators
//! above either of those.

use std::collections::BTreeMap;

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use cc_frontend::visibility::python_visibility;
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{function_signature, is_async_function, node_text};
use crate::lift::{declares_edge, lift_children_into, parent_edge};

/// Lift a `decorated_definition` — the wrapper node tree-sitter-python
/// emits when one or more `@decorator` lines precede a function or class.
pub(crate) fn lift_decorated(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let decorators = collect_decorator_names(node, ctx.bytes());
    let inner = node
        .child_by_field_name("definition")
        .unwrap_or_else(|| last_named_child(node));
    match inner.kind() {
        "function_definition" => lift_function(ctx, store, inner, parent, &decorators),
        "class_definition" => lift_class_with_decorators(ctx, store, inner, parent, &decorators),
        _ => super::generic_unresolved(ctx, store, inner),
    }
}

/// Lift a `function_definition`, optionally enriched with already-collected
/// decorator names from a wrapping `decorated_definition`.
pub(crate) fn lift_function(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
    extra_decorators: &[String],
) -> NodeId {
    let signature = function_signature(node, ctx.bytes());
    let is_async = is_async_function(node, ctx.bytes());
    let is_method = ctx.inside_class();
    let kind = if is_method {
        NodeKind::Method
    } else {
        NodeKind::Function
    };
    let decorators = merged_decorators(extra_decorators);
    let lang_ext = function_lang_ext(is_async, is_method, &decorators);
    let builder = base_named_node_builder(store, node, ctx.bytes(), kind, &decorators)
        .with_prop("signature", intern_string(store, &signature))
        .with_prop(
            "line_start",
            Value::Uint((node.start_position().row + 1) as u64),
        )
        .with_prop(
            "line_end",
            Value::Uint((node.end_position().row + 1) as u64),
        )
        .with_prop("is_async", Value::Bool(is_async))
        .with_prop("lang_ext", Value::Map(lang_ext));
    let id = store.push_node(builder);
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

/// Build a [`NodeBuilder`] with the props common to every named,
/// decoratable Python definition: `name` (from the `name` child),
/// `range` (from the tree-sitter range), and `decorators` (joined with
/// commas). Both `lift_function` and `lift_class_with_decorators`
/// extend the result with their kind-specific props.
fn base_named_node_builder(
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    bytes: &[u8],
    kind: NodeKind,
    decorators: &[String],
) -> NodeBuilder {
    let name = node
        .child_by_field_name("name")
        .map_or(String::new(), |n| node_text(n, bytes).to_owned());
    let vis = python_visibility(&name);
    let builder = NodeBuilder::new(kind)
        .with_prop("name", intern_string(store, &name))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("decorators", Value::String(decorators.join(",")));
    vis.stamp(builder)
}

/// Build the `lang_ext` map for a function — captures method-ness +
/// async classification + the original decorator list.
fn function_lang_ext(
    is_async: bool,
    is_method: bool,
    decorators: &[String],
) -> BTreeMap<String, Value> {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("is_method".to_owned(), Value::Bool(is_method));
    map.insert(
        "is_classmethod".to_owned(),
        Value::Bool(decorators.iter().any(|d| d == "classmethod")),
    );
    map.insert(
        "is_staticmethod".to_owned(),
        Value::Bool(decorators.iter().any(|d| d == "staticmethod")),
    );
    map.insert("decorators".to_owned(), Value::String(decorators.join(",")));
    map.insert(
        "async_kind".to_owned(),
        Value::String(if is_async {
            "coroutine".to_owned()
        } else {
            "none".to_owned()
        }),
    );
    map
}

/// Merge in `extra_decorators` collected from a wrapping
/// `decorated_definition` — currently a pass-through; reserved as the
/// integration point for inline decorator parsing if we add it.
fn merged_decorators(extra_decorators: &[String]) -> Vec<String> {
    extra_decorators.to_vec()
}

/// Lift a `class_definition` (no surrounding decorator block).
pub(crate) fn lift_class(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    lift_class_with_decorators(ctx, store, node, parent, &[])
}

/// Shared implementation: `lift_class` + `lift_decorated` both end here.
fn lift_class_with_decorators(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
    decorators: &[String],
) -> NodeId {
    let supers = node
        .child_by_field_name("superclasses")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let builder = base_named_node_builder(store, node, ctx.bytes(), NodeKind::Class, decorators)
        .with_prop("superclasses", intern_string(store, &supers));
    let id = store.push_node(builder);
    declares_edge(store, parent, id);
    ctx.class_depth += 1;
    if let Some(body) = node.child_by_field_name("body") {
        lift_children_into(ctx, store, body, id);
    }
    ctx.class_depth -= 1;
    id
}

/// Lift the `parameters` child of a `function_definition` into a sequence
/// of [`NodeKind::Parameter`] nodes, preserving positional order.
fn lift_parameters(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    params: TsNode<'_>,
    function_id: NodeId,
) {
    let mut cursor = params.walk();
    let mut after_star = false;
    for (idx, child) in params.named_children(&mut cursor).enumerate() {
        if child.kind() == "list_splat_pattern" || child.kind() == "list_splat" {
            after_star = true;
        }
        let id = build_parameter(ctx, store, child, idx, after_star);
        parent_edge(store, id, function_id);
    }
}

/// Build a single [`NodeKind::Parameter`] node from a parameter child.
fn build_parameter(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    position: usize,
    is_keyword_only: bool,
) -> NodeId {
    let (name, default) = parameter_name_and_default(node, ctx.bytes());
    let is_self = position == 0 && (name == "self" || name == "cls") && ctx.inside_class();
    let builder = NodeBuilder::new(NodeKind::Parameter)
        .with_prop("name", intern_string(store, &name))
        .with_prop("default", intern_string(store, &default))
        .with_prop("is_keyword_only", Value::Bool(is_keyword_only))
        .with_prop("is_self", Value::Bool(is_self))
        .with_prop("position", Value::Uint(position as u64))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Extract `(name, default_text)` from a parameter child, supporting the
/// common shapes: bare identifier, typed parameter, default parameter,
/// `*args`, `**kwargs`.
fn parameter_name_and_default(node: TsNode<'_>, bytes: &[u8]) -> (String, String) {
    let name_node = node.child_by_field_name("name").or_else(|| {
        if node.kind() == "identifier" {
            Some(node)
        } else {
            None
        }
    });
    let name = name_node.map_or(String::new(), |n| node_text(n, bytes).to_owned());
    let default = node
        .child_by_field_name("value")
        .map_or(String::new(), |n| node_text(n, bytes).to_owned());
    (name, default)
}

/// Walk the immediate children of a `decorated_definition` collecting the
/// decorator name expressions (without the leading `@`).
fn collect_decorator_names(node: TsNode<'_>, bytes: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|c| c.kind() == "decorator")
        .map(|d| decorator_text(d, bytes))
        .collect()
}

/// Strip the leading `@` and any trailing newline from a `decorator` node.
fn decorator_text(node: TsNode<'_>, bytes: &[u8]) -> String {
    let raw = node_text(node, bytes).trim();
    raw.trim_start_matches('@').trim().to_owned()
}

/// Last-resort fallback when `decorated_definition` doesn't expose the
/// `definition` field — return the final named child.
fn last_named_child(node: TsNode<'_>) -> TsNode<'_> {
    let mut cursor = node.walk();
    let last = node.named_children(&mut cursor).last();
    last.unwrap_or(node)
}
