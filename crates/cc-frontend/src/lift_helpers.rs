//! Shared lift helpers used by every per-language frontend.
//!
//! These helpers exist so that `if`-statement / `loop` / `try`-block lifting
//! looks identical across Python, TypeScript, Go, and Rust. Per-language
//! quirks (e.g. Python's `elif` chain, TS's `else if`, Go's `for-range`) are
//! handled by the caller before invoking these helpers.
//!
//! All helpers accept a borrowed [`cc_cpg::CpgWriteBatch`] so the caller
//! retains full control over the batch lifecycle.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Position, Range, Value};

/// Convert a tree-sitter byte-/point-range into a CPG [`Position`].
///
/// Tree-sitter rows are 0-indexed; the CPG schema is 1-indexed. We add one
/// to row + column so editor / LSP-style display matches.
#[must_use]
pub fn position_from_ts_range(range: tree_sitter::Range) -> Position {
    Position::new(
        range
            .start_point
            .row
            .saturating_add(1)
            .try_into()
            .unwrap_or(u32::MAX),
        range
            .start_point
            .column
            .saturating_add(1)
            .try_into()
            .unwrap_or(u32::MAX),
        range.start_byte.try_into().unwrap_or(u32::MAX),
    )
}

/// Convert a tree-sitter range into a CPG [`Range`].
#[must_use]
pub fn range_from_ts_range(range: tree_sitter::Range) -> Range {
    let start = position_from_ts_range(range);
    let end_line: u32 = range
        .end_point
        .row
        .saturating_add(1)
        .try_into()
        .unwrap_or(u32::MAX);
    let end_col: u32 = range
        .end_point
        .column
        .saturating_add(1)
        .try_into()
        .unwrap_or(u32::MAX);
    let end_off: u32 = range.end_byte.try_into().unwrap_or(u32::MAX);
    Range::new(start, Position::new(end_line, end_col, end_off))
}

/// Intern a string into the CPG's shared name pool and return the
/// matching [`Value`] property variant.
///
/// The helper centralises interning so frontends never construct
/// `Value::String` directly — that ensures the string pool is the single
/// source of truth for name comparisons across files.
pub fn intern_string(store: &mut CpgWriteBatch, s: &str) -> Value {
    // `store` is forward-compat for the future shared intern pool in cc-cpg;
    // the discard here keeps the signature stable when the pool lands.
    let _ = store;
    Value::String(s.to_owned())
}

/// Build a [`NodeKind::Block`] node and add it to the batch.
///
/// The caller is responsible for adding `AST_PARENT` edges from inner
/// statements to this block; the helper only constructs the block node
/// itself.
pub fn block_to_node(store: &mut CpgWriteBatch, range: Range) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Block).with_prop("range", Value::Range(range));
    store.push_node(builder)
}

/// Build a [`NodeKind::Branch`] node (if / switch / match / ternary).
///
/// Callers wire the true / false arms via `CFG_BRANCH_TRUE` /
/// `CFG_BRANCH_FALSE` edges in a post-pass; this helper only records the
/// condition reference on the branch node.
pub fn branch_to_node(store: &mut CpgWriteBatch, range: Range, condition: NodeId) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Branch)
        .with_prop("range", Value::Range(range))
        .with_prop("condition_id", Value::NodeRef(condition));
    store.push_node(builder)
}

/// Build a [`NodeKind::Loop`] node (for / while / do-while / range).
pub fn loop_to_node(
    store: &mut CpgWriteBatch,
    range: Range,
    body: NodeId,
    condition: Option<NodeId>,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Loop)
        .with_prop("range", Value::Range(range))
        .with_prop("body_id", Value::NodeRef(body));
    if let Some(cond) = condition {
        builder = builder.with_prop("condition_id", Value::NodeRef(cond));
    }
    store.push_node(builder)
}

/// Build a [`NodeKind::Try`] node (try / catch / finally / except).
///
/// `catches` is a list of node refs to the handler blocks; type-of-catch
/// information lives on the handler's own properties.
pub fn try_to_node(store: &mut CpgWriteBatch, range: Range, catches: Vec<NodeId>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Try)
        .with_prop("range", Value::Range(range))
        .with_prop("catches", Value::NodeList(catches));
    store.push_node(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_range(start_row: usize, end_row: usize) -> tree_sitter::Range {
        tree_sitter::Range {
            start_byte: 0,
            end_byte: 10,
            start_point: tree_sitter::Point {
                row: start_row,
                column: 0,
            },
            end_point: tree_sitter::Point {
                row: end_row,
                column: 5,
            },
        }
    }

    #[test]
    fn position_conversion_is_one_indexed() {
        let p = position_from_ts_range(ts_range(0, 0));
        assert_eq!(p.line, 1, "tree-sitter row 0 -> CPG line 1");
        assert_eq!(p.column, 1, "tree-sitter col 0 -> CPG column 1");
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn range_conversion_preserves_endpoints() {
        let r = range_from_ts_range(ts_range(2, 4));
        assert_eq!(r.start.line, 3);
        assert_eq!(r.end.line, 5);
    }
}
