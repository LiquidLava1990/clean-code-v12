//! Lifters for control-flow + block statements.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{
    block_to_node, branch_to_node, intern_string, loop_to_node, range_from_ts_range, try_to_node,
};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;
use crate::lift::{lift_children_into, lift_node, parent_edge};

/// Lift `if_statement` / `match_statement` into a `Branch` node.
pub(crate) fn lift_branch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let condition = lift_branch_condition(ctx, store, node);
    let id = branch_to_node(store, range_from_ts_range(node.range()), condition);
    parent_edge(store, condition, id);
    lift_branch_consequence(ctx, store, node, id);
    lift_branch_alternative(ctx, store, node, id);
    id
}

/// Build a placeholder identifier for the branch condition — we lift the
/// real condition expression as a child via the `condition` field when
/// present, falling back to a synthetic `Unresolved` marker.
fn lift_branch_condition(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let cond_field = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("subject"));
    if let Some(cond) = cond_field {
        if let Some(id) = lift_node(ctx, store, cond, NodeId::new(1)) {
            return id;
        }
    }
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, "<condition>"))
        .with_prop("resolves_to", intern_string(store, "Unresolved"));
    store.push_node(builder)
}

/// Lift the `consequence` body of a branch, if present.
fn lift_branch_consequence(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    if let Some(body) = node.child_by_field_name("consequence") {
        if let Some(id) = lift_node(ctx, store, body, branch_id) {
            parent_edge(store, id, branch_id);
        }
    }
    // `match_statement` exposes its arms as named `case_clause` children
    // rather than a `consequence` field.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "case_clause" {
            if let Some(id) = lift_node(ctx, store, child, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
}

/// Lift the `alternative` (else / elif) chain of an `if_statement`.
fn lift_branch_alternative(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "elif_clause" | "else_clause") {
            if let Some(id) = lift_node(ctx, store, child, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
}

/// Lift `for_statement` / `while_statement` into a `Loop` node.
pub(crate) fn lift_loop(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let body_id = node
        .child_by_field_name("body")
        .and_then(|b| lift_node(ctx, store, b, NodeId::new(1)))
        .unwrap_or_else(|| placeholder_block(store, node));
    let condition = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("right"))
        .and_then(|c| lift_node(ctx, store, c, NodeId::new(1)));
    let id = loop_to_node(store, range_from_ts_range(node.range()), body_id, condition);
    parent_edge(store, body_id, id);
    if let Some(c) = condition {
        parent_edge(store, c, id);
    }
    id
}

/// Build an empty `Block` placeholder when a control-flow node has no body.
fn placeholder_block(store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    block_to_node(store, range_from_ts_range(node.range()))
}

/// Lift a `try_statement` — emits a `Try` node and links every
/// `except_clause` as a catches entry.
pub(crate) fn lift_try(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let mut cursor = node.walk();
    let mut catches: Vec<NodeId> = Vec::new();
    let mut body_id: Option<NodeId> = None;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "block" if body_id.is_none() => {
                body_id = lift_node(ctx, store, child, NodeId::new(1));
            }
            "except_clause" | "except_group_clause" => {
                catches.push(build_except(ctx, store, child));
            }
            _ => {}
        }
    }
    let try_id = try_to_node(store, range_from_ts_range(node.range()), catches.clone());
    if let Some(b) = body_id {
        parent_edge(store, b, try_id);
    }
    for c in catches {
        parent_edge(store, c, try_id);
    }
    try_id
}

/// Build a single `Try`-catch entry from an `except_clause` — captures
/// the exception type text (or `Exception` if elided).
fn build_except(ctx: &mut LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let exception_type = extract_exception_type(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Try)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("exception_type", intern_string(store, &exception_type));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}

/// Extract the exception type text from an `except_clause`. Returns the
/// first non-keyword named child's bare type name (with any `as <alias>`
/// stripped), or the empty string when the clause has no type at all
/// (truly bare `except:`).
///
/// Downstream rules rely on this distinction: `cc.error.bare` fires only
/// on the empty-string marker; `cc.error.broad_catch` matches on the
/// bare type name (`Exception`, `BaseException`, `Error`, `Throwable`).
/// If we returned `"Exception"` for truly-bare excepts, the two cases
/// would be indistinguishable; if we returned `"Exception as e"` for
/// the typed form, the broad_catch lookup would fail to match.
fn extract_exception_type(node: TsNode<'_>, bytes: &[u8]) -> String {
    let mut cursor = node.walk();
    for c in node.named_children(&mut cursor) {
        if matches!(
            c.kind(),
            "block" | "as_pattern_target" | "identifier_pattern"
        ) {
            continue;
        }
        // tree-sitter wraps `Exception as e` as an `as_pattern` whose
        // first named child is the bare type. Walk into it; otherwise
        // return the child's own text.
        let raw = if c.kind() == "as_pattern" {
            first_named_child_text(c, bytes)
        } else {
            node_text(c, bytes).to_owned()
        };
        return strip_as_alias(&raw);
    }
    String::new()
}

/// Return the text of the first named child, falling back to the node's
/// own text when it has no named children.
fn first_named_child_text(node: TsNode<'_>, bytes: &[u8]) -> String {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next();
    match first {
        Some(c) => node_text(c, bytes).to_owned(),
        None => node_text(node, bytes).to_owned(),
    }
}

/// Strip a trailing `as <ident>` alias, defensively. Some frontends
/// produce already-clean text via `as_pattern`; others produce raw text
/// `"Exception as e"`. Both shapes are normalised here.
fn strip_as_alias(raw: &str) -> String {
    raw.split_whitespace().next().unwrap_or("").to_owned()
}

/// Lift a `block` into a `Block` node and recurse into its children.
pub(crate) fn lift_block(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let id = block_to_node(store, range_from_ts_range(node.range()));
    lift_children_into(ctx, store, node, id);
    id
}

/// Lift `return_statement` / `yield` / `raise_statement` as `Return`.
pub(crate) fn lift_return(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let kind_label = match node.kind() {
        "return_statement" => "return",
        "yield" => "yield",
        "raise_statement" => "raise",
        other => other,
    };
    let builder = NodeBuilder::new(NodeKind::Return)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("return_kind", intern_string(store, kind_label));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}

/// Lift an `expression_statement` — flattens to its (single) inner
/// expression so we don't double-nest the AST. Returns `None` for empty
/// statements (rare, e.g. trailing semicolons).
pub(crate) fn lift_expression_statement(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next()?;
    lift_node(ctx, store, first, parent)
}
