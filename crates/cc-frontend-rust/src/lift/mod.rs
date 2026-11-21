//! Lift dispatcher — converts a tree-sitter Rust tree into CPG nodes.
//!
//! The lifter is a depth-first walker. Each `lift_*` function appends to a
//! [`cc_cpg::CpgWriteBatch`] and returns the [`NodeId`] it produced; the
//! caller is responsible for wiring the resulting node to its parent via
//! [`cc_cpg::EdgeKind::AST_PARENT`].
//!
//! # Lift policy
//!
//! - Tree-sitter `ERROR` / `MISSING` nodes are logged via [`tracing::warn`]
//!   and replaced with a [`cc_cpg::NodeKind::Identifier`] carrying
//!   `name = "<error>"`. This keeps the AST contiguous so downstream queries
//!   can still walk the parent chain.
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

/// Lift the root `source_file` node into the CPG and return the `File` id.
///
/// The lifter is non-fatal: any node it can't handle is recorded as an
/// `Identifier` marker and walking continues. The only path that returns
/// `Err(LiftError)` is a non-`source_file` root, which indicates a grammar /
/// runtime mismatch the caller should surface.
///
/// # Errors
///
/// Returns [`LiftError`] if the root node is not the `source_file` produced
/// by tree-sitter-rust.
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
            "expected `source_file` root from tree-sitter-rust; \
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

/// Construct the top-level `File` node carrying `language` + `file_id`.
fn build_file_node(store: &mut CpgWriteBatch, ctx: &LiftCtx<'_>, root: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::File)
        .with_prop("language", intern_string(store, "rust"))
        .with_prop("file_id", Value::Uint(ctx.file_id.raw()))
        .with_prop("range", Value::Range(range_from_ts_range(root.range())));
    store.push_node(builder)
}

/// Construct the `Module` child of the `File`.
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
/// Returns `Some(node_id)` when a CPG node was created. The only path that
/// returns `None` is an empty `expression_statement` — a rare edge case
/// (trailing semicolon at top level) where there is genuinely nothing to
/// lift; the parent walker drops the slot.
pub(crate) fn lift_node(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    if node.is_error() || node.is_missing() {
        return Some(error_marker(ctx, store, node));
    }
    // `expression_statement` is the lone dispatch that may legitimately
    // return `None` (empty body); every other branch returns a concrete id.
    if node.kind() == "expression_statement" {
        return statement::lift_expression_statement(ctx, store, node, parent);
    }
    if let Some(id) = dispatch_item(ctx, store, node, parent) {
        return Some(id);
    }
    if let Some(id) = dispatch_control(ctx, store, node, parent) {
        return Some(id);
    }
    if let Some(id) = dispatch_expression(ctx, store, node, parent) {
        return Some(id);
    }
    if let Some(id) = dispatch_misc(ctx, store, node, parent) {
        return Some(id);
    }
    Some(generic_unresolved(ctx, store, node))
}

/// Dispatch table for top-level items (functions, classes, impls).
fn dispatch_item(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "function_item" | "function_signature_item" => {
            Some(function::lift_function(ctx, store, node, parent))
        }
        "impl_item" => Some(function::lift_impl(ctx, store, node, parent)),
        "struct_item" | "enum_item" | "trait_item" | "union_item" => {
            Some(function::lift_class(ctx, store, node, parent))
        }
        _ => None,
    }
}

/// Dispatch table for control-flow expressions + blocks + try/await.
fn dispatch_control(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "if_expression" | "match_expression" => {
            Some(statement::lift_branch(ctx, store, node, parent))
        }
        "for_expression" | "while_expression" | "loop_expression" => {
            Some(statement::lift_loop(ctx, store, node, parent))
        }
        "try_expression" | "try_block" => Some(statement::lift_try(ctx, store, node, parent)),
        "block" | "block_expression" => Some(statement::lift_block(ctx, store, node, parent)),
        "return_expression" => Some(statement::lift_return(ctx, store, node, parent)),
        "await_expression" => Some(expression::lift_await(ctx, store, node, parent)),
        _ => None,
    }
}

/// Dispatch table for plain expressions, identifiers, and literals.
fn dispatch_expression(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "let_declaration" => Some(expression::lift_let(ctx, store, node, parent)),
        "assignment_expression" | "compound_assignment_expr" => {
            Some(expression::lift_assignment(ctx, store, node, parent))
        }
        "call_expression" | "method_call_expression" => {
            Some(expression::lift_call(ctx, store, node, parent))
        }
        "macro_invocation" => Some(expression::lift_macro(ctx, store, node, parent)),
        "identifier" | "field_identifier" | "type_identifier" | "shorthand_field_identifier" => {
            Some(expression::lift_identifier(ctx, store, node))
        }
        "string_literal" | "raw_string_literal" | "integer_literal" | "float_literal"
        | "boolean_literal" | "char_literal" => Some(expression::lift_literal(ctx, store, node)),
        _ => None,
    }
}

/// Dispatch table for imports / attributes / comments. Takes `&LiftCtx` —
/// these lifters are read-only over context.
fn dispatch_misc(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "use_declaration" | "extern_crate_declaration" => {
            Some(import::lift_import(ctx, store, node))
        }
        "attribute_item" | "inner_attribute_item" => Some(import::lift_attribute(ctx, store, node)),
        "line_comment" | "block_comment" => Some(import::lift_comment(ctx, store, node)),
        _ => None,
    }
}

/// Emit an `AST_PARENT` edge from `child` to `parent`.
///
/// `push_edge` returns `Err` only on a dangling endpoint, which can't happen
/// here because both ids were just produced by the same batch.
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
        target: "cc_frontend_rust",
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
