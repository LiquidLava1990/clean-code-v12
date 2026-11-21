//! Lifters for TypeScript function-shaped nodes (`function_declaration`,
//! `function_expression`, `method_definition`, `arrow_function`,
//! `generator_function_declaration`) and class-shaped nodes
//! (`class_declaration`, `interface_declaration`, `class`).

use std::collections::BTreeMap;

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use cc_frontend::visibility::typescript_visibility;
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::{
    function_name, function_signature, generic_type_param_names, is_async_function,
    is_generator_function, is_react_component, node_text,
};
use crate::lift::{declares_edge, lift_children_into, lift_node, parent_edge};

/// True iff `node` is wrapped in an `export_statement` /
/// `export_default_statement` (directly or via a `lexical_declaration` /
/// `variable_declaration` intermediary).
fn is_node_exported(node: TsNode<'_>) -> bool {
    let mut cur = node.parent();
    let mut hops = 0;
    while let Some(p) = cur {
        if matches!(p.kind(), "export_statement" | "export_default_statement") {
            return true;
        }
        if !matches!(
            p.kind(),
            "lexical_declaration"
                | "variable_declaration"
                | "variable_declarator"
                | "ambient_declaration"
        ) {
            return false;
        }
        hops += 1;
        if hops > 4 {
            return false;
        }
        cur = p.parent();
    }
    false
}

/// Read the `accessibility_modifier` child source text — TS class
/// members may carry a `public` / `private` / `protected` keyword.
fn member_accessibility<'a>(node: TsNode<'_>, bytes: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "accessibility_modifier" {
            return Some(node_text(child, bytes));
        }
    }
    None
}

/// Try to handle `node` as a function- or class-shaped construct.
///
/// Returns `None` if `node.kind()` is not one we own — the dispatcher then
/// hands the node to the next sibling module.
pub(crate) fn dispatch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "function_declaration"
        | "function_expression"
        | "generator_function_declaration"
        | "generator_function" => Some(lift_function(ctx, store, node, parent)),
        "method_definition" | "method_signature" | "abstract_method_signature" => {
            Some(lift_method(ctx, store, node, parent))
        }
        "arrow_function" => Some(lift_arrow(ctx, store, node, parent)),
        "class_declaration" | "class" | "abstract_class_declaration" => {
            Some(lift_class(ctx, store, node, parent))
        }
        "interface_declaration" => Some(lift_interface(ctx, store, node, parent)),
        "export_statement" | "export_default_statement" => {
            Some(lift_export_wrapper(ctx, store, node, parent))
        }
        _ => None,
    }
}

/// Lift an `export_statement` / `export_default_statement` by forwarding
/// to the wrapped declaration. This keeps DECLARES edges + decorator
/// hoisting working uniformly with non-exported declarations.
///
/// If no recognised inner declaration is present (e.g. `export { foo };`
/// re-exports), we fall back to a generic unresolved marker.
fn lift_export_wrapper(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "function_declaration"
                | "function_expression"
                | "generator_function_declaration"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
                | "lexical_declaration"
                | "variable_declaration"
        ) {
            if let Some(id) = dispatch(ctx, store, child, parent) {
                return id;
            }
        }
    }
    super::generic_unresolved(ctx, store, node)
}

/// Lift a `function_declaration` / `function_expression` /
/// `generator_function_declaration` into a [`NodeKind::Function`] node.
pub(crate) fn lift_function(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    lift_function_like(
        ctx,
        store,
        node,
        parent,
        FunctionLiftSpec {
            is_arrow: false,
            kind: NodeKind::Function,
            emit_module_declares: true,
        },
    )
}

/// Lift a `method_definition` (and the TS-specific `method_signature` /
/// `abstract_method_signature` shapes) into a [`NodeKind::Method`] node.
fn lift_method(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    lift_function_like(
        ctx,
        store,
        node,
        parent,
        FunctionLiftSpec {
            is_arrow: false,
            kind: NodeKind::Method,
            emit_module_declares: false,
        },
    )
}

/// Lift an `arrow_function`. The `is_arrow` flag in the `lang_ext` map is
/// the discriminator downstream queries use to tell arrow vs declared
/// functions apart.
fn lift_arrow(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    let kind = if ctx.inside_class() {
        NodeKind::Method
    } else {
        NodeKind::Function
    };
    lift_function_like(
        ctx,
        store,
        node,
        parent,
        FunctionLiftSpec {
            is_arrow: true,
            kind,
            emit_module_declares: false,
        },
    )
}

/// Per-call-site knobs for the shared function-lifter body. `is_arrow`
/// flows into `FunctionInfo::collect` to set the arrow flag in
/// `lang_ext`; `kind` selects between `Function` and `Method` CPG node
/// kinds; `emit_module_declares` is true only for top-level declared
/// functions (methods + arrows are wired by their enclosing scope).
struct FunctionLiftSpec {
    is_arrow: bool,
    kind: NodeKind,
    emit_module_declares: bool,
}

/// Shared body for `lift_function`, `lift_method`, and `lift_arrow`.
/// Each variant only differs in the spec passed in: SimHash flagged the
/// per-variant 3-line glue as cross-function duplication before this
/// helper landed.
fn lift_function_like(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
    spec: FunctionLiftSpec,
) -> NodeId {
    let info = FunctionInfo::collect(ctx, node, spec.is_arrow);
    let id = build_function_node(store, node, &info, spec.kind);
    if spec.emit_module_declares && !ctx.inside_class() {
        if let Some(module) = ctx.module_id {
            declares_edge(store, module, id);
        }
    }
    let _ = parent;
    lift_function_body(ctx, store, node, id);
    id
}

/// Build the actual `Function` / `Method` CPG node from collected info.
fn build_function_node(
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    info: &FunctionInfo,
    kind: NodeKind,
) -> NodeId {
    let lang_ext = function_lang_ext(info);
    let visibility = typescript_visibility(info.is_exported, info.member_accessibility.as_deref());
    let builder = NodeBuilder::new(kind)
        .with_prop("name", intern_string(store, &info.name))
        .with_prop("signature", intern_string(store, &info.signature))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop(
            "line_start",
            Value::Uint((node.start_position().row + 1) as u64),
        )
        .with_prop(
            "line_end",
            Value::Uint((node.end_position().row + 1) as u64),
        )
        .with_prop("is_async", Value::Bool(info.is_async))
        .with_prop("lang_ext", Value::Map(lang_ext));
    let builder = visibility.stamp(builder);
    store.push_node(builder)
}

/// Lift the function's parameters + body, attaching them to `function_id`.
fn lift_function_body(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    function_id: NodeId,
) {
    if let Some(params) = node.child_by_field_name("parameters") {
        lift_parameters(ctx, store, params, function_id);
    }
    if let Some(body) = node.child_by_field_name("body") {
        if let Some(body_id) = lift_node(ctx, store, body, function_id) {
            parent_edge(store, body_id, function_id);
        }
    }
}

/// Aggregate the per-function flags we record on the CPG node.
///
/// Each boolean represents an orthogonal axis of the TypeScript function
/// schema (async / arrow / generator / method / React-component) — they
/// can't be reduced to a smaller enum without losing information.
#[allow(clippy::struct_excessive_bools)]
struct FunctionInfo {
    name: String,
    signature: String,
    is_async: bool,
    is_arrow: bool,
    is_generator: bool,
    is_method: bool,
    is_react_component: bool,
    generics: Vec<String>,
    overloads: u64,
    is_exported: bool,
    member_accessibility: Option<String>,
}

impl FunctionInfo {
    fn collect(ctx: &LiftCtx<'_>, node: TsNode<'_>, is_arrow: bool) -> Self {
        let bytes = ctx.bytes();
        let name = function_name(node, bytes);
        let signature = function_signature(node, bytes);
        let is_async = is_async_function(node, bytes);
        let is_generator = is_generator_function(node, bytes);
        let generics = generic_type_param_names(node, bytes);
        let is_method = ctx.inside_class();
        let is_react_component = is_react_component(node, &name);
        let overloads = count_overloads(node, &name, bytes);
        let is_exported = is_node_exported(node);
        let member_accessibility = member_accessibility(node, bytes).map(str::to_owned);
        Self {
            name,
            signature,
            is_async,
            is_arrow,
            is_generator,
            is_method,
            is_react_component,
            generics,
            overloads,
            is_exported,
            member_accessibility,
        }
    }
}

/// Count overload siblings that share `name` within the immediate parent.
///
/// TypeScript expresses overloads as multiple `function_declaration` /
/// `method_signature` siblings followed by the implementation. The count
/// returned excludes `node` itself — the implementation site sees how many
/// overload signatures preceded it.
fn count_overloads(node: TsNode<'_>, name: &str, bytes: &[u8]) -> u64 {
    if name.is_empty() {
        return 0;
    }
    let Some(parent) = node.parent() else {
        return 0;
    };
    let mut cursor = parent.walk();
    parent
        .named_children(&mut cursor)
        .filter(|sib| sib.id() != node.id() && shares_name(*sib, name, bytes))
        .count() as u64
}

/// Does `sib` declare a function-shaped node with `name`?
fn shares_name(sib: TsNode<'_>, name: &str, bytes: &[u8]) -> bool {
    if !is_function_shaped(sib.kind()) {
        return false;
    }
    sib.child_by_field_name("name")
        .is_some_and(|n| node_text(n, bytes) == name)
}

/// Tree-sitter-typescript kinds that participate in overload counting.
const fn is_function_shaped(kind: &str) -> bool {
    matches!(
        kind.as_bytes(),
        b"function_declaration"
            | b"function_expression"
            | b"method_definition"
            | b"method_signature"
            | b"abstract_method_signature"
            | b"generator_function_declaration"
    )
}

/// Build the `lang_ext` map for a function, capturing the TS-specific
/// extension fields documented in `docs/design/CPG_SCHEMA.md`.
fn function_lang_ext(info: &FunctionInfo) -> BTreeMap<String, Value> {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("is_arrow".to_owned(), Value::Bool(info.is_arrow));
    map.insert("is_method".to_owned(), Value::Bool(info.is_method));
    map.insert("is_generator".to_owned(), Value::Bool(info.is_generator));
    map.insert(
        "is_react_component".to_owned(),
        Value::Bool(info.is_react_component),
    );
    map.insert(
        "generics".to_owned(),
        Value::String(info.generics.join(",")),
    );
    map.insert("overloads".to_owned(), Value::Uint(info.overloads));
    map.insert(
        "async_kind".to_owned(),
        Value::String(if info.is_async {
            "coroutine".to_owned()
        } else {
            "none".to_owned()
        }),
    );
    map
}

/// Lift a `class_declaration` / `class` / `abstract_class_declaration`.
pub(crate) fn lift_class(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    lift_class_like(ctx, store, node, parent, /* is_interface */ false)
}

/// Lift an `interface_declaration` — a TypeScript-only construct that we
/// model as a `Class` for query parity (the body is structurally identical
/// to a class minus implementations).
fn lift_interface(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    lift_class_like(ctx, store, node, parent, /* is_interface */ true)
}

/// Shared body for `lift_class` and `lift_interface`. Both flavours
/// build the same `ClassInfo`, push a `Class` CPG node (with the
/// `is_interface` flag flipping the relevant `lang_ext` field), wire
/// the `DECLARES` edge, and lift the body's children. The only
/// behavioural difference is the boolean flag.
fn lift_class_like(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
    is_interface: bool,
) -> NodeId {
    let info = ClassInfo::collect(ctx, node);
    let id = build_class_node(store, node, &info, is_interface);
    record_class_declares(ctx, store, parent, id);
    ctx.class_depth += 1;
    if let Some(body) = node.child_by_field_name("body") {
        lift_children_into(ctx, store, body, id);
    }
    ctx.class_depth -= 1;
    id
}

/// Issue the `DECLARES` edge from the owning `Module` (top-level) or skip
/// if the class is itself nested in another class / function.
fn record_class_declares(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    parent: NodeId,
    class_id: NodeId,
) {
    let _ = parent;
    if ctx.inside_class() {
        return;
    }
    if let Some(module) = ctx.module_id {
        declares_edge(store, module, class_id);
    }
}

/// Aggregate the per-class flags we record on the CPG node.
struct ClassInfo {
    name: String,
    decorators: Vec<String>,
    generics: Vec<String>,
    extends: String,
    implements: String,
    is_exported: bool,
}

impl ClassInfo {
    fn collect(ctx: &LiftCtx<'_>, node: TsNode<'_>) -> Self {
        let bytes = ctx.bytes();
        let name = node
            .child_by_field_name("name")
            .map_or(String::new(), |n| node_text(n, bytes).to_owned());
        let decorators = collect_class_decorators(node, bytes);
        let generics = generic_type_param_names(node, bytes);
        let extends = extract_clause(node, bytes, "extends_clause");
        let implements = extract_clause(node, bytes, "implements_clause");
        let is_exported = is_node_exported(node);
        Self {
            name,
            decorators,
            generics,
            extends,
            implements,
            is_exported,
        }
    }
}

/// Build the actual `Class` CPG node from collected info.
fn build_class_node(
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    info: &ClassInfo,
    is_interface: bool,
) -> NodeId {
    let mut lang_ext: BTreeMap<String, Value> = BTreeMap::new();
    lang_ext.insert("is_interface".to_owned(), Value::Bool(is_interface));
    lang_ext.insert(
        "generics".to_owned(),
        Value::String(info.generics.join(",")),
    );
    lang_ext.insert("extends".to_owned(), Value::String(info.extends.clone()));
    lang_ext.insert(
        "implements".to_owned(),
        Value::String(info.implements.clone()),
    );
    let visibility = typescript_visibility(info.is_exported, None);
    let builder = NodeBuilder::new(NodeKind::Class)
        .with_prop("name", intern_string(store, &info.name))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("decorators", Value::String(info.decorators.join(",")))
        .with_prop("lang_ext", Value::Map(lang_ext));
    let builder = visibility.stamp(builder);
    store.push_node(builder)
}

/// Walk every named child of `params` and lift it as a [`NodeKind::Parameter`].
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

/// Build a single [`NodeKind::Parameter`] node from a `formal_parameters`
/// child (`required_parameter` / `optional_parameter` / `rest_pattern`).
fn build_parameter(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    position: usize,
) -> NodeId {
    let (name, default, type_text) = parameter_name_default_type(node, ctx.bytes());
    let is_optional = node.kind() == "optional_parameter";
    let is_rest = node.kind() == "rest_pattern";
    let builder = NodeBuilder::new(NodeKind::Parameter)
        .with_prop("name", intern_string(store, &name))
        .with_prop("default", intern_string(store, &default))
        .with_prop("type_text", intern_string(store, &type_text))
        .with_prop("is_optional", Value::Bool(is_optional))
        .with_prop("is_rest", Value::Bool(is_rest))
        .with_prop("position", Value::Uint(position as u64))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Extract `(name, default_text, type_text)` from a parameter child.
fn parameter_name_default_type(node: TsNode<'_>, bytes: &[u8]) -> (String, String, String) {
    let name_node = node.child_by_field_name("pattern").or_else(|| {
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
    let type_text = node
        .child_by_field_name("type")
        .map_or(String::new(), |n| node_text(n, bytes).to_owned());
    (name, default, type_text)
}

/// Collect decorators attached to a class declaration.
///
/// Tree-sitter-typescript places decorators in two different positions
/// depending on context:
///
/// - Bare `@deco class Foo {}` -> `decorator` is a direct child of
///   `class_declaration`.
/// - Exported `export @deco class Foo {}` -> the decorator is hoisted to
///   the wrapping `export_statement`, becoming a *sibling* of the
///   `class_declaration` rather than a child.
///
/// We check both positions so the public surface is uniform.
fn collect_class_decorators(node: TsNode<'_>, bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    push_decorators_from(&mut out, node, bytes);
    if let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "export_statement" | "export_default_statement"
        ) {
            push_decorators_from(&mut out, parent, bytes);
        }
    }
    out
}

/// Append every immediate `decorator` child of `node` to `out`.
fn push_decorators_from(out: &mut Vec<String>, node: TsNode<'_>, bytes: &[u8]) {
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        if c.kind() == "decorator" {
            let raw = node_text(c, bytes).trim();
            out.push(raw.trim_start_matches('@').trim().to_owned());
        }
    }
}

/// Extract the text of a class clause (`extends_clause` / `implements_clause`).
fn extract_clause(node: TsNode<'_>, bytes: &[u8], kind: &str) -> String {
    let mut cursor = node.walk();
    for c in node.named_children(&mut cursor) {
        if c.kind() == kind || c.kind() == kind.trim_end_matches("_clause") {
            return node_text(c, bytes).to_owned();
        }
    }
    if let Some(heritage) = node.child_by_field_name("heritage") {
        return node_text(heritage, bytes).to_owned();
    }
    String::new()
}
