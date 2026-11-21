//! Lifters for control-flow + block statements.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{
    block_to_node, branch_to_node, intern_string, loop_to_node, range_from_ts_range, try_to_node,
};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;
use crate::lift::{lift_children_into, lift_node, parent_edge};

/// Try to handle `node` as a control-flow / block / return-shaped statement.
pub(crate) fn dispatch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "if_statement" | "switch_statement" => Some(lift_branch(ctx, store, node, parent)),
        "ternary_expression" => Some(lift_ternary(ctx, store, node, parent)),
        "for_statement" | "while_statement" | "do_statement" | "for_in_statement"
        | "for_of_statement" => Some(lift_loop(ctx, store, node, parent)),
        "try_statement" => Some(lift_try(ctx, store, node, parent)),
        "statement_block" => Some(lift_block(ctx, store, node, parent)),
        "return_statement" | "throw_statement" | "yield_expression" => {
            Some(lift_return(ctx, store, node, parent))
        }
        "expression_statement" => lift_expression_statement(ctx, store, node, parent),
        _ => None,
    }
}

/// Lift `if_statement` / `switch_statement` into a [`NodeKind::Branch`].
fn lift_branch(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let condition = lift_branch_condition(ctx, store, node);
    let id = branch_to_node(store, range_from_ts_range(node.range()), condition);
    parent_edge(store, condition, id);
    lift_branch_arms(ctx, store, node, id);
    id
}

/// Lift a `ternary_expression` (`cond ? then : else`) into a Branch.
fn lift_ternary(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let condition = node
        .child_by_field_name("condition")
        .and_then(|c| lift_node(ctx, store, c, NodeId::new(1)))
        .unwrap_or_else(|| placeholder_identifier(store, "<condition>"));
    let id = branch_to_node(store, range_from_ts_range(node.range()), condition);
    parent_edge(store, condition, id);
    for field in &["consequence", "alternative"] {
        if let Some(arm) = node.child_by_field_name(field) {
            if let Some(arm_id) = lift_node(ctx, store, arm, id) {
                parent_edge(store, arm_id, id);
            }
        }
    }
    id
}

/// Build the branch condition node from `condition` / `value` field.
fn lift_branch_condition(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let cond_field = node
        .child_by_field_name("condition")
        .or_else(|| node.child_by_field_name("value"));
    if let Some(cond) = cond_field {
        if let Some(id) = lift_node(ctx, store, cond, NodeId::new(1)) {
            return id;
        }
    }
    placeholder_identifier(store, "<condition>")
}

/// Build a synthetic Identifier marker — used when a field that was
/// expected to exist is missing (almost always inside a partial parse).
fn placeholder_identifier(store: &mut CpgWriteBatch, name: &str) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Identifier)
        .with_prop("name", intern_string(store, name))
        .with_prop("resolves_to", intern_string(store, "Unresolved"));
    store.push_node(builder)
}

/// Lift the consequence / alternative arms of an `if_statement` plus the
/// `switch_body` / `switch_case` arms of a `switch_statement`.
fn lift_branch_arms(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    branch_id: NodeId,
) {
    for field in &["consequence", "alternative", "body"] {
        if let Some(arm) = node.child_by_field_name(field) {
            if let Some(id) = lift_node(ctx, store, arm, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "else_clause" | "switch_case" | "switch_default"
        ) {
            if let Some(id) = lift_node(ctx, store, child, branch_id) {
                parent_edge(store, id, branch_id);
            }
        }
    }
}

/// Lift `for_statement` / `while_statement` / `do_statement` /
/// `for_in_statement` / `for_of_statement` into a [`NodeKind::Loop`].
fn lift_loop(
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
/// `catch_clause` as a catches entry.
fn lift_try(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let mut cursor = node.walk();
    let mut catches: Vec<NodeId> = Vec::new();
    let mut body_id: Option<NodeId> = None;
    let mut finally_id: Option<NodeId> = None;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "statement_block" if body_id.is_none() => {
                body_id = lift_node(ctx, store, child, NodeId::new(1));
            }
            "catch_clause" => {
                catches.push(build_catch(ctx, store, child));
            }
            "finally_clause" => {
                finally_id = lift_node(ctx, store, child, NodeId::new(1));
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
    if let Some(f) = finally_id {
        parent_edge(store, f, try_id);
    }
    try_id
}

/// Build a single Try-catch entry from a `catch_clause`. TypeScript catches
/// expose the binding pattern via the `parameter` field; the type
/// annotation (when present) lives as a `type_annotation` child of that
/// pattern.
fn build_catch(ctx: &mut LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let exception_type = extract_catch_type(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Try)
        .with_prop("range", Value::Range(range_from_ts_range(node.range())))
        .with_prop("exception_type", intern_string(store, &exception_type));
    let id = store.push_node(builder);
    lift_children_into(ctx, store, node, id);
    id
}

/// Extract the catch parameter type annotation, falling back to the
/// parameter binder text or `unknown` if neither is present.
fn extract_catch_type(node: TsNode<'_>, bytes: &[u8]) -> String {
    let Some(param) = node.child_by_field_name("parameter") else {
        return "unknown".to_owned();
    };
    if let Some(annotation) = param.child_by_field_name("type") {
        return node_text(annotation, bytes)
            .trim_start_matches(':')
            .trim()
            .to_owned();
    }
    let mut cursor = param.walk();
    for c in param.named_children(&mut cursor) {
        if c.kind() == "type_annotation" {
            return node_text(c, bytes)
                .trim_start_matches(':')
                .trim()
                .to_owned();
        }
    }
    node_text(param, bytes).to_owned()
}

/// Lift a `statement_block` into a `Block` node and recurse.
fn lift_block(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let id = block_to_node(store, range_from_ts_range(node.range()));
    lift_children_into(ctx, store, node, id);
    id
}

/// Lift `return_statement` / `throw_statement` / `yield_expression`
/// uniformly as [`NodeKind::Return`] with a `return_kind` discriminator.
fn lift_return(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let kind_label = match node.kind() {
        "return_statement" => "return",
        "throw_statement" => "throw",
        "yield_expression" => "yield",
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
/// statements.
fn lift_expression_statement(
    ctx: &mut LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next()?;
    lift_node(ctx, store, first, parent)
}
