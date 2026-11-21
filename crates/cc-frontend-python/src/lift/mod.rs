//! Lift dispatcher — converts a tree-sitter Python tree into CPG nodes.
//!
//! The lifter is a depth-first walker. Each `lift_*` function appends to a
//! [`cc_cpg::CpgWriteBatch`] and returns the [`NodeId`] it produced; the
//! caller is responsible for wiring the resulting node to its parent via
//! [`cc_cpg::EdgeKind::AST_PARENT`].
//!
//! # Lift policy
//!
//! - Tree-sitter `ERROR` / `MISSING` nodes are logged via
//!   [`tracing::warn`] and replaced with a [`cc_cpg::NodeKind::Identifier`]
//!   carrying `name = "<error>"`. This keeps the AST contiguous so
//!   downstream queries can still walk the parent chain.
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

/// Lift the root `module` node into the CPG and return the `File` node id.
///
/// The lifter is non-fatal: any node it can't handle is recorded as an
/// `Unresolved` marker and walking continues. The only path that returns
/// `Err(LiftError)` is a non-`module` root, which indicates a grammar /
/// runtime mismatch the caller should surface.
///
/// # Errors
///
/// Returns [`LiftError`] if the root node is not the `module` produced by
/// tree-sitter-python (catastrophic — the grammar is wrong, not just the
/// source).
pub(crate) fn lift_module(
    tree: &TreeSitterTree,
    source: &str,
    store: &mut CpgWriteBatch,
    file_id: FileId,
) -> Result<NodeId, LiftError> {
    let root = tree.root_node();
    if root.kind() != "module" {
        return Err(LiftError::new(
            root.kind(),
            cc_frontend::lift_helpers::position_from_ts_range(root.range()),
            "expected `module` root from tree-sitter-python; \
             check the grammar version pinned in Cargo.toml",
        ));
    }
    let mut ctx = LiftCtx::new(source, file_id);
    let file_node = build_file_node(store, &ctx, root);
    let module_node = build_module_node(store, root);
    parent_edge(store, module_node, file_node);
    lift_children_into(&mut ctx, store, root, module_node);
    Ok(file_node)
}

/// Construct the top-level `File` node carrying `path`/`language`/`file_id`.
fn build_file_node(store: &mut CpgWriteBatch, ctx: &LiftCtx<'_>, root: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::File)
        .with_prop("language", intern_string(store, "python"))
        .with_prop("file_id", Value::Uint(ctx.file_id.raw()))
        .with_prop("range", Value::Range(range_from_ts_range(root.range())));
    store.push_node(builder)
}

/// Construct the `Module` node child of the `File`.
fn build_module_node(store: &mut CpgWriteBatch, root: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Module)
        .with_prop("range", Value::Range(range_from_ts_range(root.range())));
    store.push_node(builder)
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
/// Returns `Some(node_id)` when a CPG node was created. Decorators attached
/// to a `decorated_definition` are absorbed by the underlying
/// function/class lifter, so we sometimes return `None` for siblings that
/// were already merged.
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
        "function_definition" => Some(function::lift_function(ctx, store, node, parent, &[])),
        "class_definition" => Some(function::lift_class(ctx, store, node, parent)),
        "decorated_definition" => Some(function::lift_decorated(ctx, store, node, parent)),
        "if_statement" | "match_statement" => {
            Some(statement::lift_branch(ctx, store, node, parent))
        }
        "for_statement" | "while_statement" => Some(statement::lift_loop(ctx, store, node, parent)),
        "try_statement" => Some(statement::lift_try(ctx, store, node, parent)),
        "block" => Some(statement::lift_block(ctx, store, node, parent)),
        "return_statement" | "yield" | "raise_statement" => {
            Some(statement::lift_return(ctx, store, node, parent))
        }
        "expression_statement" => statement::lift_expression_statement(ctx, store, node, parent),
        "assignment" | "augmented_assignment" => {
            Some(expression::lift_assignment(ctx, store, node, parent))
        }
        "call" => Some(expression::lift_call(ctx, store, node, parent)),
        "identifier" => Some(expression::lift_identifier(ctx, store, node)),
        "string" | "integer" | "float" | "true" | "false" | "none" => {
            Some(expression::lift_literal(ctx, store, node))
        }
        "await" => Some(expression::lift_await(ctx, store, node, parent)),
        "import_statement" | "import_from_statement" | "future_import_statement" => {
            Some(import::lift_import(ctx, store, node))
        }
        "decorator" => Some(import::lift_decorator(ctx, store, node, parent)),
        "comment" => Some(import::lift_comment(ctx, store, node)),
        _ => Some(generic_unresolved(ctx, store, node)),
    }
}

/// Emit an `AST_PARENT` edge from `child` to `parent`.
///
/// `push_edge` returns `Err` only on a dangling endpoint, which can't
/// happen here because both ids were just produced by the same batch.
pub(crate) fn parent_edge(store: &mut CpgWriteBatch, child: NodeId, parent: NodeId) {
    let _ = store.push_edge(EdgeKind::AST_PARENT, child, parent);
}

/// Emit a `DECLARES` edge from `module` to a top-level binding.
pub(crate) fn declares_edge(store: &mut CpgWriteBatch, module: NodeId, sym: NodeId) {
    let _ = store.push_edge(EdgeKind::DECLARES, module, sym);
}

/// Replace an `ERROR` / `MISSING` tree-sitter node with an `Identifier`
/// marker so the AST stays contiguous.
fn error_marker(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let pos = cc_frontend::lift_helpers::position_from_ts_range(node.range());
    tracing::warn!(
        target: "cc_frontend_python",
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
    // Recurse so children of the unknown node still appear in the graph.
    lift_children_into(ctx, store, node, id);
    id
}
