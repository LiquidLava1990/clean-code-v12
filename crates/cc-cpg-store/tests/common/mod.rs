//! Shared test helpers.
#![allow(dead_code)] // some tests don't use every helper
#![allow(clippy::doc_markdown)]

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Value};
use cc_cpg_store::CpgStore;
use tempfile::TempDir;

pub struct TempStore {
    pub dir: TempDir,
    pub store: CpgStore,
    pub path: Utf8PathBuf,
}

impl TempStore {
    pub fn fresh() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let raw = dir.path().join("cpg.redb");
        let path = Utf8PathBuf::from_path_buf(raw).expect("utf8 tmp path");
        let store = CpgStore::open(path.clone()).expect("open fresh");
        Self { dir, store, path }
    }
}

/// Build a minimal batch: a `File` node, three children of varied kinds, and
/// `AST_PARENT` edges from each child back to the file.
pub fn sample_batch() -> (CpgWriteBatch, NodeId, Vec<NodeId>) {
    let mut batch = CpgWriteBatch::new();
    let file = batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("a.py".into()))
            .with_prop("language", Value::String("python".into())),
    );
    let func = batch.push_node(
        NodeBuilder::new(NodeKind::Function).with_prop("name", Value::String("greet".into())),
    );
    let cls = batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("Greeter".into())),
    );
    let var = batch.push_node(
        NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String("x".into())),
    );
    batch.push_edge(EdgeKind::AST_PARENT, func, file).unwrap();
    batch.push_edge(EdgeKind::AST_PARENT, cls, file).unwrap();
    batch.push_edge(EdgeKind::AST_PARENT, var, func).unwrap();
    (batch, file, vec![func, cls, var])
}
