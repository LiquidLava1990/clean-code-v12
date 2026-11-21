//! Lift dispatcher — converts a tree-sitter TypeScript tree into CPG nodes.
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
//!   carrying `name = "<error>"` and `resolves_to = "Unresolved"`. This
//!   keeps the AST contiguous so downstream queries can still walk the
//!   parent chain.
//! - Unknown node kinds become a generic `Identifier` with the original
//!   tree-sitter `kind` recorded in `ts_kind`. The frontend never panics on
//!   an unrecognised node.

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

/// Lift the root `program` node into the CPG and return the `File` node id.
///
/// The lifter is non-fatal: any node it can't handle is recorded as an
/// `Unresolved` marker and walking continues. The only path that returns
/// `Err(LiftError)` is a non-`program` root, which indicates a grammar /
/// runtime mismatch the caller should surface.
///
/// # Errors
///
/// Returns [`LiftError`] if the root node is not the `program` produced by
/// tree-sitter-typescript (catastrophic — the grammar is wrong, not just
/// the source).
pub(crate) fn lift_program(
    tree: &TreeSitterTree,
    source: &str,
    store: &mut CpgWriteBatch,
    file_id: FileId,
) -> Result<NodeId, LiftError> {
    let root = tree.root_node();
    if root.kind() != "program" {
        return Err(LiftError::new(
            root.kind(),
            cc_frontend::lift_helpers::position_from_ts_range(root.range()),
            "expected `program` root from tree-sitter-typescript; \
             check the grammar version pinned in Cargo.toml",
        ));
    }
    let mut ctx = LiftCtx::new(source, file_id);
    let file_node = build_file_node(store, &ctx, root);
    let module_node = build_module_node(store, root);
    parent_edge(store, module_node, file_node);
    ctx.module_id = Some(module_node);
    lift_children_into(&mut ctx, store, root, module_node);
    Ok(file_node)
}

/// Construct the top-level `File` node carrying `language` / `file_id` /
/// `range` props. The CLI populates `path` later via the kernel — frontends
/// are path-agnostic.
fn build_file_node(store: &mut CpgWriteBatch, ctx: &LiftCtx<'_>, root: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::File)
        .with_prop("language", intern_string(store, "typescript"))
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
/// Returns `Some(node_id)` when a CPG node was created. The default for
/// any kind we don't yet model is a generic `Unresolved` marker so the
/// AST stays walkable. The [`Option`] return type mirrors the Python
/// frontend's contract — currently every dispatch path produces a node,
/// but reserving `None` keeps the door open for "skip this child"
/// dispatcher entries (e.g. trailing semicolons handled by their parent).
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn lift_node(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    if node.is_error() || node.is_missing() {
        return Some(error_marker(ctx, store, node));
    }
    Some(dispatch(ctx, store, node, parent))
}

/// Pure dispatch table — split out so [`lift_node`] stays small enough to
/// satisfy the workspace `too_many_lines` lint while still covering the
/// full TypeScript grammar surface. Always produces a node (falling back
/// to the unresolved marker), so the return type is `NodeId` rather than
/// `Option<NodeId>`.
fn dispatch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> NodeId {
    if let Some(id) = function::dispatch(ctx, store, node, parent) {
        return id;
    }
    if let Some(id) = statement::dispatch(ctx, store, node, parent) {
        return id;
    }
    if let Some(id) = expression::dispatch(ctx, store, node, parent) {
        return id;
    }
    if let Some(id) = import::dispatch(ctx, store, node, parent) {
        return id;
    }
    generic_unresolved(ctx, store, node)
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
        target: "cc_frontend_typescript",
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
