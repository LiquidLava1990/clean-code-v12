//! Query helpers over [`cc_cpg::CpgWriteBatch`].
//!
//! `CpgWriteBatch` exposes only the raw `nodes()` / `edges()` slices. These
//! helpers add the read-side ergonomics that frontend post-passes (name
//! resolution, type inference, call resolution) need without each one
//! re-implementing edge filtering.
//!
//! The implementations are O(N) over the full batch — fine for per-file
//! resolution at construction time. The persistent store (`cc-cpg-store`,
//! Phase 1 W1.T3) provides indexed equivalents for repo-wide queries.

use cc_cpg::{CpgWriteBatch, Edge, EdgeKind, Node, NodeId, NodeKind, Range, Value};

/// Look up a node by id.
#[must_use]
pub fn node_by_id(batch: &CpgWriteBatch, id: NodeId) -> Option<&Node> {
    batch.nodes().iter().find(|n| n.id == id)
}

/// Return the kind of the node with the given id, if it exists in the batch.
#[must_use]
pub fn node_kind(batch: &CpgWriteBatch, id: NodeId) -> Option<NodeKind> {
    node_by_id(batch, id).map(|n| n.kind)
}

/// Iterate every node of the requested kind.
pub fn nodes_of_kind(batch: &CpgWriteBatch, kind: NodeKind) -> impl Iterator<Item = &Node> {
    batch.nodes().iter().filter(move |n| n.kind == kind)
}

/// Read a string-valued property off a node, if both the node and the
/// property are present.
#[must_use]
pub fn string_prop<'b>(batch: &'b CpgWriteBatch, id: NodeId, key: &str) -> Option<&'b str> {
    match node_by_id(batch, id)?.prop(key)? {
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Read a [`Range`]-valued property off a node, if both the node and the
/// property are present.
#[must_use]
pub fn range_prop(batch: &CpgWriteBatch, id: NodeId, key: &str) -> Option<Range> {
    match node_by_id(batch, id)?.prop(key)? {
        Value::Range(r) => Some(*r),
        _ => None,
    }
}

/// Read an integer-valued (`Value::Int`) property off a node.
#[must_use]
pub fn int_prop(batch: &CpgWriteBatch, id: NodeId, key: &str) -> Option<i64> {
    match node_by_id(batch, id)?.prop(key)? {
        Value::Int(v) => Some(*v),
        _ => None,
    }
}

/// Read a boolean-valued property off a node.
#[must_use]
pub fn bool_prop(batch: &CpgWriteBatch, id: NodeId, key: &str) -> Option<bool> {
    match node_by_id(batch, id)?.prop(key)? {
        Value::Bool(v) => Some(*v),
        _ => None,
    }
}

/// Iterate every edge whose `from` matches `id` and whose kind matches.
pub fn outgoing_edges_of_kind(
    batch: &CpgWriteBatch,
    id: NodeId,
    kind: EdgeKind,
) -> impl Iterator<Item = &Edge> {
    batch
        .edges()
        .iter()
        .filter(move |e| e.from == id && e.kind == kind)
}

/// Iterate every edge whose `to` matches `id` and whose kind matches.
pub fn incoming_edges_of_kind(
    batch: &CpgWriteBatch,
    id: NodeId,
    kind: EdgeKind,
) -> impl Iterator<Item = &Edge> {
    batch
        .edges()
        .iter()
        .filter(move |e| e.to == id && e.kind == kind)
}

/// First outgoing edge target of the requested kind, if any.
#[must_use]
pub fn first_outgoing_target(batch: &CpgWriteBatch, id: NodeId, kind: EdgeKind) -> Option<NodeId> {
    outgoing_edges_of_kind(batch, id, kind).next().map(|e| e.to)
}

/// Convenience: AST parent of `id` (the `to` end of the outgoing AST_PARENT).
///
/// CPG semantics: `AST_PARENT` points from child → parent, so the parent
/// lives at the edge's `to` end.
#[must_use]
pub fn ast_parent(batch: &CpgWriteBatch, id: NodeId) -> Option<NodeId> {
    first_outgoing_target(batch, id, EdgeKind::AST_PARENT)
}

/// Convenience: every direct AST child of `parent` (incoming AST_PARENT).
pub fn ast_children<'b>(
    batch: &'b CpgWriteBatch,
    parent: NodeId,
) -> impl Iterator<Item = NodeId> + 'b {
    incoming_edges_of_kind(batch, parent, EdgeKind::AST_PARENT).map(|e| e.from)
}

/// Property keys frontends use to record the callee identity of a
/// [`NodeKind::Call`] node. Order is not significant — the helper
/// concatenates every present slot so substring-matching probes see a
/// uniform haystack regardless of which lift convention populated it.
const CALLEE_PROP_KEYS: &[&str] = &[
    "callee_ref",
    "name",
    "signature",
    "qualified",
    "callee",
    "method",
];

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Frontends store callee identity inconsistently across languages
/// (Python lifts to `name`, Rust to `signature`/`qualified`, JS to
/// `callee`, Go to `qualified`/`method`). This helper concatenates
/// every present slot — separated by single spaces — into one haystack
/// rule packs can substring-match without re-implementing the merge in
/// every pack helper.
///
/// Returns an empty string when the node carries none of the candidate
/// slots (caller decides whether to treat empty as "no signal" or
/// "unresolved callee"). The companion [`callee_text_opt`] returns
/// `None` for the empty case if that's more ergonomic at the call site.
#[must_use]
pub fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    let mut buf = String::new();
    for key in CALLEE_PROP_KEYS {
        if let Some(value) = string_prop(batch, id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    buf
}

/// `Option`-returning variant of [`callee_text`]. `None` when no
/// candidate slot is populated; otherwise `Some(non_empty_string)`.
#[must_use]
pub fn callee_text_opt(batch: &CpgWriteBatch, id: NodeId) -> Option<String> {
    let buf = callee_text(batch, id);
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeKind, Value};

    fn named(batch: &mut CpgWriteBatch, kind: NodeKind, name: &str) -> NodeId {
        batch.push_node(NodeBuilder::new(kind).with_prop("name", Value::String(name.to_owned())))
    }

    #[test]
    fn node_kind_round_trip() {
        let mut b = CpgWriteBatch::new();
        let id = named(&mut b, NodeKind::Variable, "x");
        assert_eq!(node_kind(&b, id), Some(NodeKind::Variable));
    }

    #[test]
    fn string_prop_reads_existing_key() {
        let mut b = CpgWriteBatch::new();
        let id = named(&mut b, NodeKind::Identifier, "x");
        assert_eq!(string_prop(&b, id, "name"), Some("x"));
        assert_eq!(string_prop(&b, id, "missing"), None);
    }

    #[test]
    fn ast_parent_follows_child_to_parent() {
        let mut b = CpgWriteBatch::new();
        let parent = named(&mut b, NodeKind::Module, "m");
        let child = named(&mut b, NodeKind::Function, "f");
        b.push_edge(EdgeKind::AST_PARENT, child, parent).unwrap();
        assert_eq!(ast_parent(&b, child), Some(parent));
        assert_eq!(ast_parent(&b, parent), None);
    }

    #[test]
    fn ast_children_lists_only_direct() {
        let mut b = CpgWriteBatch::new();
        let parent = named(&mut b, NodeKind::Module, "m");
        let a = named(&mut b, NodeKind::Function, "a");
        let c = named(&mut b, NodeKind::Function, "b");
        b.push_edge(EdgeKind::AST_PARENT, a, parent).unwrap();
        b.push_edge(EdgeKind::AST_PARENT, c, parent).unwrap();
        let children: Vec<NodeId> = ast_children(&b, parent).collect();
        assert_eq!(children.len(), 2);
        assert!(children.contains(&a));
        assert!(children.contains(&c));
    }

    #[test]
    fn callee_text_concatenates_every_present_slot() {
        let mut b = CpgWriteBatch::new();
        let id = b.push_node(
            NodeBuilder::new(NodeKind::Call)
                .with_prop("name", Value::String("time.sleep".to_owned()))
                .with_prop("qualified", Value::String("std.time.sleep".to_owned())),
        );
        let text = callee_text(&b, id);
        assert!(text.contains("time.sleep"));
        assert!(text.contains("std.time.sleep"));
        // Single-space separator, no leading/trailing space.
        assert!(!text.starts_with(' '));
        assert!(!text.ends_with(' '));
    }

    #[test]
    fn callee_text_empty_when_no_slots_present() {
        let mut b = CpgWriteBatch::new();
        let id = b.push_node(NodeBuilder::new(NodeKind::Call));
        assert_eq!(callee_text(&b, id), "");
        assert_eq!(callee_text_opt(&b, id), None);
    }

    #[test]
    fn callee_text_opt_returns_some_when_any_slot_present() {
        let mut b = CpgWriteBatch::new();
        let id = b.push_node(
            NodeBuilder::new(NodeKind::Call).with_prop("method", Value::String("recv".to_owned())),
        );
        assert_eq!(callee_text_opt(&b, id).as_deref(), Some("recv"));
    }

    #[test]
    fn callee_text_recognises_method_slot() {
        // The `method` key was historically only used by tests_the_mock /
        // memory packs; verify it lands in the canonical haystack.
        let mut b = CpgWriteBatch::new();
        let id = b.push_node(
            NodeBuilder::new(NodeKind::Call)
                .with_prop("callee", Value::String("self".to_owned()))
                .with_prop("method", Value::String("send".to_owned())),
        );
        let text = callee_text(&b, id);
        assert!(text.contains("self"));
        assert!(text.contains("send"));
    }
}
