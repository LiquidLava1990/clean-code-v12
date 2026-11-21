//! Batch write path — atomically inserts a [`CpgWriteBatch`] plus indexes.
//!
//! All writes for one batch happen inside one redb write transaction so a
//! crash mid-batch never produces a partial graph. The summary returned to
//! the caller is computed before commit and reported only after the commit
//! succeeds.
//!
//! # Id remapping
//!
//! [`cc_cpg::CpgWriteBatch`] hands out node and edge ids starting at `1`,
//! independently per batch. The store keeps a global high-water mark for
//! both ids in the `meta` table; on each write we offset the incoming batch
//! by that mark before persisting. This keeps every persisted id unique
//! across the lifetime of the store while letting frontends remain ignorant
//! of the global counter.

use std::collections::HashMap;

use cc_cpg::{CpgWriteBatch, Edge, EdgeId, Node, NodeId};
use cc_frontend::FileId;

use crate::codec;
use crate::error::{StoreError, StoreResult};
use crate::meta;
use crate::tables::{self, edge_kind_tag, node_kind_tag};

/// Counts and id-remapping returned to the caller after `write_batch`.
///
/// `node_id_map` and `edge_id_map` translate the batch-local ids (which
/// always start at `1` per [`cc_cpg::CpgWriteBatch`]) into the globally
/// unique ids assigned by the store. Callers that intend to query the
/// freshly-written nodes by id MUST consult these maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteSummary {
    /// Number of node rows written.
    pub nodes_written: u64,
    /// Number of edge rows written.
    pub edges_written: u64,
    /// Sum of bincode-encoded byte length for nodes + edges.
    pub bytes: u64,
    /// Mapping from batch-local NodeId → store-global NodeId.
    pub node_id_map: HashMap<NodeId, NodeId>,
    /// Mapping from batch-local EdgeId → store-global EdgeId.
    pub edge_id_map: HashMap<EdgeId, EdgeId>,
}

/// Insert a finished batch into the store.
///
/// The `file_id` is stamped into the `by_file` index for every node, allowing
/// O(N) per-file invalidation later.
pub(crate) fn write_batch(
    db: &redb::Database,
    file_id: FileId,
    batch: CpgWriteBatch,
) -> StoreResult<WriteSummary> {
    let (nodes, edges) = batch.into_parts();
    let txn = db
        .begin_write()
        .map_err(|e| StoreError::txn("begin_write", e))?;

    let node_base = meta::read_counter(&txn, meta::NEXT_NODE_ID_KEY, 1)?;
    let edge_base = meta::read_counter(&txn, meta::NEXT_EDGE_ID_KEY, 1)?;

    let mut summary = WriteSummary::default();
    summary.node_id_map.reserve(nodes.len());
    summary.edge_id_map.reserve(edges.len());

    {
        let mut ctx = WriteCtx::open(&txn)?;
        for (offset, node) in nodes.iter().enumerate() {
            let new_id = NodeId::new(node_base + offset as u64);
            summary.node_id_map.insert(node.id, new_id);
            let remapped = remap_node(node, new_id);
            summary.bytes += ctx.write_node(&remapped, file_id)? as u64;
        }
        for (offset, edge) in edges.iter().enumerate() {
            let new_id = EdgeId::new(edge_base + offset as u64);
            summary.edge_id_map.insert(edge.id, new_id);
            let remapped = remap_edge(edge, new_id, &summary.node_id_map)?;
            summary.bytes += ctx.write_edge(&remapped)? as u64;
        }
    }

    summary.nodes_written = nodes.len() as u64;
    summary.edges_written = edges.len() as u64;

    meta::write_counter(&txn, meta::NEXT_NODE_ID_KEY, node_base + nodes.len() as u64)?;
    meta::write_counter(&txn, meta::NEXT_EDGE_ID_KEY, edge_base + edges.len() as u64)?;

    txn.commit().map_err(StoreError::commit)?;
    Ok(summary)
}

fn remap_node(node: &Node, new_id: NodeId) -> Node {
    let mut clone = node.clone();
    clone.id = new_id;
    clone
}

fn remap_edge(
    edge: &Edge,
    new_id: EdgeId,
    node_map: &HashMap<NodeId, NodeId>,
) -> StoreResult<Edge> {
    let from = node_map
        .get(&edge.from)
        .copied()
        .ok_or_else(|| StoreError::Integrity {
            detail: format!(
                "edge {:?} references node {:?} not in this batch",
                edge.id, edge.from
            ),
        })?;
    let to = node_map
        .get(&edge.to)
        .copied()
        .ok_or_else(|| StoreError::Integrity {
            detail: format!(
                "edge {:?} references node {:?} not in this batch",
                edge.id, edge.to
            ),
        })?;
    let mut clone = edge.clone();
    clone.id = new_id;
    clone.from = from;
    clone.to = to;
    Ok(clone)
}

/// All open table handles needed for one batch. Bundling them keeps each
/// per-row method short (Tier-0 R-FN-LEN).
struct WriteCtx<'txn> {
    nodes: redb::Table<'txn, u64, &'static [u8]>,
    edges: redb::Table<'txn, u64, &'static [u8]>,
    by_kind: redb::Table<'txn, (u8, u64), ()>,
    by_file: redb::Table<'txn, (u64, u64), ()>,
    edges_out: redb::Table<'txn, (u64, u8, u64), u64>,
    edges_in: redb::Table<'txn, (u64, u8, u64), u64>,
}

impl<'txn> WriteCtx<'txn> {
    fn open(txn: &'txn redb::WriteTransaction) -> StoreResult<Self> {
        Ok(Self {
            nodes: txn
                .open_table(tables::NODES)
                .map_err(|e| StoreError::table("open nodes", e))?,
            edges: txn
                .open_table(tables::EDGES)
                .map_err(|e| StoreError::table("open edges", e))?,
            by_kind: txn
                .open_table(tables::BY_KIND)
                .map_err(|e| StoreError::table("open by_kind", e))?,
            by_file: txn
                .open_table(tables::BY_FILE)
                .map_err(|e| StoreError::table("open by_file", e))?,
            edges_out: txn
                .open_table(tables::EDGES_OUT)
                .map_err(|e| StoreError::table("open edges_out", e))?,
            edges_in: txn
                .open_table(tables::EDGES_IN)
                .map_err(|e| StoreError::table("open edges_in", e))?,
        })
    }

    fn write_node(&mut self, node: &Node, file_id: FileId) -> StoreResult<usize> {
        let bytes = codec::encode("node", node)?;
        let id = node.id.get();
        self.nodes
            .insert(id, bytes.as_slice())
            .map_err(|e| StoreError::storage("nodes.insert", e))?;
        self.by_kind
            .insert((node_kind_tag(node.kind), id), ())
            .map_err(|e| StoreError::storage("by_kind.insert", e))?;
        self.by_file
            .insert((file_id.raw(), id), ())
            .map_err(|e| StoreError::storage("by_file.insert", e))?;
        Ok(bytes.len())
    }

    fn write_edge(&mut self, edge: &Edge) -> StoreResult<usize> {
        let bytes = codec::encode("edge", edge)?;
        let id = edge.id.get();
        let kind = edge_kind_tag(edge.kind);
        let from = edge.from.get();
        let to = edge.to.get();
        self.edges
            .insert(id, bytes.as_slice())
            .map_err(|e| StoreError::storage("edges.insert", e))?;
        self.edges_out
            .insert((from, kind, to), id)
            .map_err(|e| StoreError::storage("edges_out.insert", e))?;
        self.edges_in
            .insert((to, kind, from), id)
            .map_err(|e| StoreError::storage("edges_in.insert", e))?;
        Ok(bytes.len())
    }
}
