//! `nodes_of_kind`, `nodes_in_file`, `outgoing_edges`, `incoming_edges`,
//! `ast_parent`, and `ast_children` all hit the right index rows.

mod common;

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeKind, Value};
use cc_cpg_store::FileId;
use common::TempStore;

#[test]
fn nodes_of_kind_index() {
    let TempStore { store, .. } = TempStore::fresh();

    let mut batch = CpgWriteBatch::new();
    for i in 0..6u64 {
        batch.push_node(
            NodeBuilder::new(NodeKind::Function).with_prop("name", Value::String(format!("f{i}"))),
        );
    }
    for i in 0..4u64 {
        batch.push_node(
            NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String(format!("C{i}"))),
        );
    }

    store
        .write_batch(FileId::new(2), batch)
        .expect("write batch");

    let funcs: Vec<_> = store
        .nodes_of_kind(NodeKind::Function)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(funcs.len(), 6);
    assert!(funcs.iter().all(|n| n.kind == NodeKind::Function));

    let classes: Vec<_> = store
        .nodes_of_kind(NodeKind::Class)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(classes.len(), 4);

    // No methods written -> empty.
    let methods: Vec<_> = store
        .nodes_of_kind(NodeKind::Method)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert!(methods.is_empty());
}

#[test]
fn outgoing_and_incoming_edges_indexed() {
    let TempStore { store, .. } = TempStore::fresh();

    let mut batch = CpgWriteBatch::new();
    let parent_b = batch.push_node(NodeBuilder::new(NodeKind::Block));
    let child_b = batch.push_node(NodeBuilder::new(NodeKind::Variable));
    let unrelated_b = batch.push_node(NodeBuilder::new(NodeKind::Variable));
    batch
        .push_edge(EdgeKind::AST_PARENT, child_b, parent_b)
        .unwrap();

    let summary = store.write_batch(FileId::new(3), batch).expect("write");
    let parent = summary.node_id_map[&parent_b];
    let child = summary.node_id_map[&child_b];
    let unrelated = summary.node_id_map[&unrelated_b];

    let out: Vec<_> = store
        .outgoing_edges(child, EdgeKind::AST_PARENT)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(out.len(), 1);

    let cfg_next: Vec<_> = store
        .outgoing_edges(child, EdgeKind::CFG_NEXT)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert!(cfg_next.is_empty());

    let unrelated_out: Vec<_> = store
        .outgoing_edges(unrelated, EdgeKind::AST_PARENT)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert!(unrelated_out.is_empty());

    let inc: Vec<_> = store
        .incoming_edges(parent, EdgeKind::AST_PARENT)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0].from, child);

    // Convenience helpers.
    assert_eq!(store.ast_parent(child).expect("ok"), Some(parent));
    let kids: Vec<_> = store
        .ast_children(parent)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(kids, vec![child]);
}

#[test]
fn nodes_in_file_index() {
    let TempStore { store, .. } = TempStore::fresh();

    let mut batch_a = CpgWriteBatch::new();
    batch_a.push_node(NodeBuilder::new(NodeKind::File));
    batch_a.push_node(NodeBuilder::new(NodeKind::Function));
    store.write_batch(FileId::new(11), batch_a).expect("a");

    let mut batch_b = CpgWriteBatch::new();
    for _ in 0..3 {
        batch_b.push_node(NodeBuilder::new(NodeKind::Variable));
    }
    store.write_batch(FileId::new(12), batch_b).expect("b");

    let in_a: Vec<_> = store
        .nodes_in_file(FileId::new(11))
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(in_a.len(), 2);

    let in_b: Vec<_> = store
        .nodes_in_file(FileId::new(12))
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(in_b.len(), 3);
}
