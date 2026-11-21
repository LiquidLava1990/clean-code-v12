//! A batch written through the public API is fully recoverable via the
//! indexed read API.

mod common;

use cc_cpg::{EdgeKind, NodeKind};
use cc_cpg_store::FileId;
use common::{sample_batch, TempStore};

#[test]
fn write_batch_round_trip() {
    let TempStore { store, .. } = TempStore::fresh();
    let (batch, batch_file_root, batch_children) = sample_batch();
    let summary = store.write_batch(FileId::new(7), batch).expect("write");
    assert_eq!(summary.nodes_written, 4);
    assert_eq!(summary.edges_written, 3);
    assert!(summary.bytes > 0);

    // Translate batch-local ids to store-global ids.
    let file_root = summary.node_id_map[&batch_file_root];
    let children: Vec<_> = batch_children
        .iter()
        .map(|id| summary.node_id_map[id])
        .collect();

    // Every node id round-trips.
    let root = store.node(file_root).expect("read").expect("present");
    assert_eq!(root.kind, NodeKind::File);

    for id in &children {
        let node = store.node(*id).expect("read").expect("present");
        assert!(matches!(
            node.kind,
            NodeKind::Function | NodeKind::Class | NodeKind::Variable
        ));
    }

    // AST_PARENT edges visible via outgoing index.
    let func = children[0];
    let parents: Vec<_> = store
        .outgoing_edges(func, EdgeKind::AST_PARENT)
        .expect("range")
        .collect::<Result<_, _>>()
        .expect("decode");
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].to, file_root);
}
