//! Lift dispatcher — converts a tree-sitter Go tree into CPG nodes.
//!
//! Depth-first walker. Each `lift_*` function appends to a
//! [`cc_cpg::CpgWriteBatch`] and returns the [`NodeId`] it produced; the
//! caller is responsible for wiring the resulting node to its parent via
//! [`cc_cpg::EdgeKind::AST_PARENT`].
//!
//! # Lift policy
//!
//! - `ERROR` / `MISSING` tree-sitter nodes are logged via [`tracing::warn`]
//!   and replaced with an [`cc_cpg::NodeKind::Identifier`] carrying
//!   `name = "<error>"`.
//! - Unknown node kinds become a generic `Identifier` with the original
//!   tree-sitter `kind` recorded in `lang_ext.kind`. The frontend never
//!   panics on an unrecognised node.

mod context;
mod expression;
mod function;
mod import;
mod statement;
mod types;

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use cc_frontend::{FileId, LiftError, TreeSitterTree};
use tree_sitter::Node as TsNode;

pub(crate) use context::LiftCtx;

/// Lift the root `source_file` node into the CPG and return the `File`
/// node id.
///
/// # Errors
///
/// Returns [`LiftError`] if the root node is not the `source_file`
/// produced by tree-sitter-go (catastrophic — the grammar is wrong).
pub(crate) fn lift_source_file(
    tree: &TreeSitterTree,
    source: &str,
    store: &mut CpgWriteBatch,
    file_id: FileId,
) -> Result<NodeId, LiftError> {
    let root = tree.root_node();
    if root.kind() != "source_file" {
        return Err(LiftError::new(
            root.kind(),
            cc_frontend::lift_helpers::position_from_ts_range(root.range()),
            "expected `source_file` root from tree-sitter-go; \
             check the grammar version pinned in Cargo.toml",
        ));
    }
    let mut ctx = LiftCtx::new(source, file_id);
    let file_node = build_file_node(store, &ctx, root);
    let module_node = build_module_node(store, &ctx, root);
    parent_edge(store, module_node, file_node);
    lift_children_into(&mut ctx, store, root, module_node);
    Ok(file_node)
}

/// Build the top-level `File` node carrying `language` + `file_id`.
fn build_file_node(store: &mut CpgWriteBatch, ctx: &LiftCtx<'_>, root: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::File)
        .with_prop("language", intern_string(store, "go"))
        .with_prop("file_id", Value::Uint(ctx.file_id.raw()))
        .with_prop("range", Value::Range(range_from_ts_range(root.range())));
    store.push_node(builder)
}

/// Build a `Module` node — Go has one package per file, so we surface the
/// `package_clause` name (or `<unknown>` on partial parses).
fn build_module_node(store: &mut CpgWriteBatch, ctx: &LiftCtx<'_>, root: TsNode<'_>) -> NodeId {
    let pkg = extract_package_name(root, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Module)
        .with_prop("name", intern_string(store, &pkg))
        .with_prop("qualified_name", intern_string(store, &pkg))
        .with_prop("range", Value::Range(range_from_ts_range(root.range())));
    store.push_node(builder)
}

/// Pull the package name from the first `package_clause` child.
fn extract_package_name(root: TsNode<'_>, bytes: &[u8]) -> String {
    let mut cursor = root.walk();
    let clause = root
        .named_children(&mut cursor)
        .find(|c| c.kind() == "package_clause");
    clause
        .and_then(|c| package_name_from_clause(c, bytes))
        .unwrap_or_else(|| "<unknown>".to_owned())
}

/// Resolve the package name within a `package_clause` — prefers the
/// `name` field, falling back to a `package_identifier` named child.
fn package_name_from_clause(clause: TsNode<'_>, bytes: &[u8]) -> Option<String> {
    if let Some(name) = clause.child_by_field_name("name") {
        return Some(types::node_text(name, bytes).trim().to_owned());
    }
    let mut cursor = clause.walk();
    let ident = clause
        .named_children(&mut cursor)
        .find(|c| c.kind() == "package_identifier");
    ident.map(|c| types::node_text(c, bytes).trim().to_owned())
}

/// Walk every named child of `parent_ts` and lift it under `parent_id`.
pub(crate) fn lift_children_into(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    parent_ts: TsNode<'_>,
    parent_id: NodeId,
) {
    let mut cursor = parent_ts.walk();
    for child in parent_ts.named_children(&mut cursor) {
        if let Some(child_id) = lift_node(ctx, store, child, parent_id) {
            parent_edge(store, child_id, parent_id);
        }
    }
}

/// Dispatch a single named tree-sitter node to its lifter.
///
/// Returns `Some(node_id)` when a CPG node was created. `package_clause`
/// is absorbed at module-build time so it returns `None`.
pub(crate) fn lift_node(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    if node.is_error() || node.is_missing() {
        return Some(error_marker(ctx, store, node));
    }
    match node.kind() {
        // Already absorbed during module construction.
        "package_clause" => None,
        "function_declaration" => Some(function::lift_function(ctx, store, node, parent)),
        "method_declaration" => Some(function::lift_method(ctx, store, node, parent)),
        "type_declaration" => Some(function::lift_type_declaration(ctx, store, node, parent)),
        "if_statement"
        | "switch_statement"
        | "type_switch_statement"
        | "select_statement"
        | "expression_switch_statement" => Some(statement::lift_branch(ctx, store, node, parent)),
        "for_statement" => Some(statement::lift_loop(ctx, store, node, parent)),
        "defer_statement" => Some(statement::lift_defer(ctx, store, node, parent)),
        "go_statement" => Some(statement::lift_go(ctx, store, node, parent)),
        "block" => Some(statement::lift_block(ctx, store, node, parent)),
        "return_statement" => Some(statement::lift_return(ctx, store, node, parent)),
        "assignment_statement"
        | "short_var_declaration"
        | "var_declaration"
        | "const_declaration" => Some(expression::lift_assignment(ctx, store, node, parent)),
        "call_expression" => Some(expression::lift_call(ctx, store, node, parent)),
        "identifier" | "type_identifier" | "field_identifier" | "package_identifier" => {
            Some(expression::lift_identifier(ctx, store, node))
        }
        "int_literal"
        | "float_literal"
        | "imaginary_literal"
        | "rune_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "true"
        | "false"
        | "nil" => Some(expression::lift_literal(ctx, store, node)),
        "import_declaration" | "import_spec" => Some(import::lift_import(ctx, store, node)),
        "comment" => Some(import::lift_comment(ctx, store, node)),
        "expression_statement" => statement::lift_expression_statement(ctx, store, node, parent),
        _ => Some(generic_unresolved(ctx, store, node)),
    }
}

/// Emit an `AST_PARENT` edge from `child` to `parent`.
pub(crate) fn parent_edge(store: &mut CpgWriteBatch, child: NodeId, parent: NodeId) {
    let _ = store.push_edge(EdgeKind::AST_PARENT, child, parent);
}

/// Emit a `DECLARES` edge from `module` to a top-level binding.
pub(crate) fn declares_edge(store: &mut CpgWriteBatch, module: NodeId, sym: NodeId) {
    let _ = store.push_edge(EdgeKind::DECLARES, module, sym);
}

/// Replace an `ERROR` / `MISSING` node with an `Identifier` marker so the
/// AST stays contiguous.
fn error_marker(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let pos = cc_frontend::lift_helpers::position_from_ts_range(node.range());
    tracing::warn!(
        target: "cc_frontend_go",
        line = pos.line,
        column = pos.column,
        kind = node.kind(),
        "lift saw error node — emitting Unresolved marker; \
         fix: correct the source or extend the lifter for this construct"
    );
    let _ = ctx;
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<error>"))
        .with_prop("resolves_to", intern_string(store, "Unresolved"))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Catch-all lifter for tree-sitter kinds we don't yet model.
fn generic_unresolved(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let kind = node.kind();
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<unresolved>"))
        .with_prop("resolves_to", intern_string(store, "Unresolved"))
        .with_prop("ts_kind", intern_string(store, kind))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}
