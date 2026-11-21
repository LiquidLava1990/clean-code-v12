//! Lifters for `function_declaration`, `method_declaration`, and
//! `type_declaration` (struct / interface bodies become Class nodes).

use std::collections::BTreeMap;

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use cc_frontend::visibility::go_visibility;
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{function_signature, method_receiver_type, node_text};
use crate::lift::{declares_edge, lift_children_into, lift_node, parent_edge};

/// Bundle of fields needed to build a `Function` / `Method` CPG node.
///
/// Groups parameters that always travel together so call sites stay
/// inside the project-wide ≤5 positional-param ceiling. Borrows the
/// tree-sitter node + an optional receiver string slice — strictly a
/// transient build descriptor, never stored.
struct FunctionNodeSpec<'a> {
    /// CPG node kind — `Function` for free functions, `Method` for those
    /// with a receiver.
    kind: NodeKind,
    /// Identifier text of the function (`""` for malformed parses).
    name: &'a str,
    /// Pre-rendered Go signature `(params) results` for diagnostics.
    signature: &'a str,
    /// Source tree-sitter node — used for range + position props.
    node: TsNode<'a>,
    /// Method receiver type (e.g. `*Foo`); `None` for free functions.
    receiver: Option<&'a str>,
    /// Pre-scanned flag — true when the body contains a `go_statement`.
    goroutine_spawned: bool,
}

/// Shape inputs for `build_function_like` — bundles the four
/// non-context arguments (tree-sitter node, parent CPG id, target node
/// kind, optional receiver) so the entry point stays at 3 positional
/// params (`ctx`, `store`, this struct).
struct FunctionLiftRequest<'a> {
    /// Tree-sitter `function_declaration` / `method_declaration` node.
    node: TsNode<'a>,
    /// Enclosing CPG parent (typically a `Module`).
    parent: NodeId,
    /// CPG node kind to emit — `Function` or `Method`.
    kind: NodeKind,
    /// Method receiver type for `Method`; `None` for free functions.
    receiver: Option<&'a str>,
}

/// Bundle of fields needed to emit a single `Parameter` CPG node.
///
/// One `parameter_declaration` may bind multiple names sharing one
/// type, so the same descriptor is built repeatedly with only `name`
/// and `position` varying — bundling cuts param count from 6 to 2.
struct ParameterSpec<'a> {
    /// Source tree-sitter node — used for range.
    node: TsNode<'a>,
    /// Parameter identifier (`""` for anonymous interface-method params).
    name: &'a str,
    /// Parameter type text.
    ty: &'a str,
    /// Zero-based position in the function's parameter list.
    position: usize,
    /// True for `...T` variadic parameters.
    is_variadic: bool,
}

/// Lift a free `function_declaration` (no receiver).
pub(crate) fn lift_function(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let req = FunctionLiftRequest {
        node,
        parent,
        kind: NodeKind::Function,
        receiver: None,
    };
    build_function_like(ctx, store, &req)
}

/// Lift a `method_declaration` — emits a [`NodeKind::Method`] with the
/// receiver type recorded both as a top-level prop and inside `lang_ext`.
pub(crate) fn lift_method(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let receiver = method_receiver_type(node, ctx.bytes());
    let req = FunctionLiftRequest {
        node,
        parent,
        kind: NodeKind::Method,
        receiver: receiver.as_deref(),
    };
    build_function_like(ctx, store, &req)
}

/// Shared body for `lift_function` + `lift_method`.
fn build_function_like(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    req: &FunctionLiftRequest<'_>,
) -> NodeId {
    let node = req.node;
    let name = node
        .child_by_field_name("name")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let signature = function_signature(node, ctx.bytes());
    let params_node = node.child_by_field_name("parameters");
    let body_node = node.child_by_field_name("body");

    // Pre-scan the body for any `go_statement` so we can stamp
    // `lang_ext.goroutine_spawned` at construction time. The CPG batch is
    // append-only (no node mutation), so this scan-then-build pattern is
    // the canonical workaround.
    let goroutine_spawned = body_node.is_some_and(contains_go_statement);

    let prev_goroutine = ctx.goroutine_spawned;
    ctx.goroutine_spawned = false;

    let spec = FunctionNodeSpec {
        kind: req.kind,
        name: &name,
        signature: &signature,
        node,
        receiver: req.receiver,
        goroutine_spawned,
    };
    let id = push_function_node(store, &spec);
    declares_edge(store, req.parent, id);

    if let Some(p) = params_node {
        lift_parameters(ctx, store, p, id);
    }
    if let Some(r) = node.child_by_field_name("receiver") {
        lift_parameters(ctx, store, r, id);
    }
    if let Some(b) = body_node {
        if let Some(body_id) = lift_node(ctx, store, b, id) {
            parent_edge(store, body_id, id);
        }
    }

    ctx.goroutine_spawned = prev_goroutine;
    id
}

/// Recursively scan a function body for any `go_statement` descendant.
///
/// We do not descend into nested `function_declaration` /
/// `func_literal` / `method_declaration` so the flag reflects only the
/// directly enclosing function (Go semantics: a `go` inside an inner
/// closure is the closure's spawn, not the outer function's).
fn contains_go_statement(body: TsNode<'_>) -> bool {
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        if child.kind() == "go_statement" {
            return true;
        }
        if matches!(
            child.kind(),
            "function_declaration" | "method_declaration" | "func_literal" | "function_type"
        ) {
            continue;
        }
        if contains_go_statement(child) {
            return true;
        }
    }
    false
}

/// Build the `Function` / `Method` node and push it into the batch.
fn push_function_node(store: &mut CpgWriteBatch, spec: &FunctionNodeSpec<'_>) -> NodeId {
    let lang_ext = function_lang_ext(spec.receiver, spec.goroutine_spawned);
    let vis = go_visibility(spec.name);
    let mut builder = NodeBuilder::new(spec.kind)
        .with_prop("name", intern_string(store, spec.name))
        .with_prop("signature", intern_string(store, spec.signature))
        .with_prop(
            "range",
            Value::Range(range_from_ts_range(spec.node.range())),
        )
        .with_prop(
            "line_start",
            Value::Uint((spec.node.start_position().row + 1) as u64),
        )
        .with_prop(
            "line_end",
            Value::Uint((spec.node.end_position().row + 1) as u64),
        )
        .with_prop("is_async", Value::Bool(false))
        .with_prop("lang_ext", Value::Map(lang_ext));
    if let Some(r) = spec.receiver {
        builder = builder.with_prop("receiver_class", intern_string(store, r));
    }
    builder = vis.stamp(builder);
    store.push_node(builder)
}

/// Build the `lang_ext` map for a Go function — captures receiver +
/// method-value + goroutine flags. `goroutine_spawned` is decided up-front
/// by a pre-scan because the CPG batch is append-only.
fn function_lang_ext(receiver: Option<&str>, goroutine_spawned: bool) -> BTreeMap<String, Value> {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert(
        "receiver_type".to_owned(),
        receiver.map_or(Value::Null, |r| Value::String(r.to_owned())),
    );
    map.insert("is_method_value".to_owned(), Value::Bool(false));
    map.insert(
        "goroutine_spawned".to_owned(),
        Value::Bool(goroutine_spawned),
    );
    map
}

/// Lift a `type_declaration`. Each `type_spec` whose body is a
/// `struct_type` or `interface_type` becomes a [`NodeKind::Class`].
pub(crate) fn lift_type_declaration(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    // Wrap multiple specs under a synthetic Block so we can return a single
    // id; for the common single-spec case this is still a Block-of-1.
    let group_id = build_group_block(store, node);
    declares_edge(store, parent, group_id);

    let mut cursor = node.walk();
    for spec in node.named_children(&mut cursor) {
        if spec.kind() == "type_spec" || spec.kind() == "type_alias" {
            if let Some(class_id) = lift_type_spec(ctx, store, spec) {
                parent_edge(store, class_id, group_id);
                declares_edge(store, parent, class_id);
            }
        }
    }
    group_id
}

/// Build the wrapper `Block` for a `type_declaration` group.
fn build_group_block(store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Block)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("kind_label", Value::String("type_group".to_owned()));
    store.push_node(builder)
}

/// Lift a single `type_spec` if its body is a struct or interface; other
/// shapes (alias, named primitive, function type) return `None`.
fn lift_type_spec(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    spec: TsNode<'_>,
) -> Option<NodeId> {
    let name = spec
        .child_by_field_name("name")
        .map_or(String::new(), |n| node_text(n, ctx.bytes()).to_owned());
    let body = spec.child_by_field_name("type")?;
    let class_kind = match body.kind() {
        "struct_type" => "struct",
        "interface_type" => "interface",
        _ => return None,
    };
    let id = push_class_node(store, &name, class_kind, spec);
    ctx.type_depth += 1;
    lift_children_into(ctx, store, body, id);
    ctx.type_depth -= 1;
    Some(id)
}

/// Build the `Class` node for a struct or interface.
fn push_class_node(
    store: &mut CpgWriteBatch,
    name: &str,
    class_kind: &str,
    spec: TsNode<'_>,
) -> NodeId {
    let vis = go_visibility(name);
    let builder = NodeBuilder::new(NodeKind::Class)
        .with_prop("name", intern_string(store, name))
        .with_prop("kind", intern_string(store, class_kind))
        .with_prop("superclasses", intern_string(store, ""))
        .with_prop("range", Value::Range(range_from_ts_range(spec.range())));
    let builder = vis.stamp(builder);
    store.push_node(builder)
}

/// Lift a `parameter_list` (or receiver list) into a sequence of
/// [`NodeKind::Parameter`] nodes, preserving positional order.
fn lift_parameters(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    params: TsNode<'_>,
    function_id: NodeId,
) {
    let mut cursor = params.walk();
    let mut idx: usize = 0;
    for child in params.named_children(&mut cursor) {
        if child.kind() != "parameter_declaration"
            && child.kind() != "variadic_parameter_declaration"
        {
            continue;
        }
        let is_variadic = child.kind() == "variadic_parameter_declaration";
        for pid in expand_parameter(ctx, store, child, idx, is_variadic) {
            parent_edge(store, pid, function_id);
            idx += 1;
        }
    }
}

/// A single `parameter_declaration` may bind multiple names sharing one
/// type — e.g. `func f(a, b int)`. Emit one `Parameter` per name so the
/// schema's `position` ordering reflects the call-site argument order.
fn expand_parameter(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    base_position: usize,
    is_variadic: bool,
) -> Vec<NodeId> {
    let type_text = node
        .child_by_field_name("type")
        .map_or(String::new(), |t| node_text(t, ctx.bytes()).to_owned());
    let names = collect_parameter_names(node, ctx.bytes());
    if names.is_empty() {
        // Anonymous parameter (common in interface method signatures).
        return vec![build_parameter(
            store,
            &ParameterSpec {
                node,
                name: "",
                ty: &type_text,
                position: base_position,
                is_variadic,
            },
        )];
    }
    names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            build_parameter(
                store,
                &ParameterSpec {
                    node,
                    name,
                    ty: &type_text,
                    position: base_position + i,
                    is_variadic,
                },
            )
        })
        .collect()
}

/// Collect every `name`-field identifier under a `parameter_declaration`.
fn collect_parameter_names(node: TsNode<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(child, bytes).to_owned());
        }
    }
    out
}

/// Build a single [`NodeKind::Parameter`] node from a [`ParameterSpec`].
fn build_parameter(store: &mut CpgWriteBatch, spec: &ParameterSpec<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Parameter)
        .with_prop("name", intern_string(store, spec.name))
        .with_prop("type", intern_string(store, spec.ty))
        .with_prop("default", intern_string(store, ""))
        .with_prop("is_variadic", Value::Bool(spec.is_variadic))
        .with_prop("position", Value::Uint(spec.position as u64))
        .with_prop(
            "range",
            Value::Range(range_from_ts_range(spec.node.range())),
        );
    store.push_node(builder)
}
