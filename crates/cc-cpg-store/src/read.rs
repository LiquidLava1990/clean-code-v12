//! Read-side query API.
//!
//! Each query opens a fresh read transaction so callers always see a
//! consistent snapshot (redb's MVCC guarantees readers don't block writers
//! and vice versa). Results are materialised eagerly into a `Vec` and
//! returned as an owned iterator — this keeps the public API a simple
//! `impl Iterator<Item = StoreResult<T>>` without leaking redb's lifetime
//! parameters.
//!
//! All the index-scanning helpers funnel through `scan_table`, and the
//! single-record helpers funnel through `fetch_record`. Both centralise the
//! "open table → handle missing-table → map redb errors" boilerplate so a
//! new index or record kind costs one call site, not one cargo-culted
//! 25-line function.

use std::vec::IntoIter;

use crate::codec;
use crate::error::{StoreError, StoreResult};
use crate::tables::{self, edge_kind_tag, node_kind_tag};
use cc_cpg::{Edge, EdgeId, EdgeKind, Node, NodeId, NodeKind};
use cc_frontend::FileId;
use redb::{Key, TableDefinition, Value};
use serde::de::DeserializeOwned;

/// Iterator type returned by read queries that yield `Node` results.
pub type NodeIter = IntoIter<StoreResult<Node>>;

/// Iterator type returned by read queries that yield `Edge` results.
pub type EdgeIter = IntoIter<StoreResult<Edge>>;

/// Iterator type for `ast_children`.
pub type NodeIdIter = IntoIter<StoreResult<NodeId>>;

/// Fetch a single node by id.
pub(crate) fn node(db: &redb::Database, id: NodeId) -> StoreResult<Option<Node>> {
    let txn = db
        .begin_read()
        .map_err(|e| StoreError::txn("begin_read", e))?;
    fetch_node(&txn, id)
}

/// Fetch a single edge by id.
pub(crate) fn edge(db: &redb::Database, id: EdgeId) -> StoreResult<Option<Edge>> {
    let txn = db
        .begin_read()
        .map_err(|e| StoreError::txn("begin_read", e))?;
    fetch_edge(&txn, id)
}

/// Read a bincode-encoded record out of a `u64 → bytes` table.
///
/// Returns `Ok(None)` when either the table itself has not been materialised
/// (a brand-new store before its first write) or the row is absent.
/// `what` is a static label used to name the table/op in error messages
/// AND as the bincode-decode label, so a single string covers all three
/// failure sites.
fn fetch_record<T: DeserializeOwned>(
    txn: &redb::ReadTransaction,
    table_def: TableDefinition<'static, u64, &'static [u8]>,
    what: &'static str,
    raw_id: u64,
) -> StoreResult<Option<T>> {
    let table = match txn.open_table(table_def) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(StoreError::table(what, e)),
    };
    let Some(row) = table
        .get(raw_id)
        .map_err(|e| StoreError::storage(what, e))?
    else {
        return Ok(None);
    };
    let value: T = codec::decode(what, row.value())?;
    Ok(Some(value))
}

fn fetch_node(txn: &redb::ReadTransaction, id: NodeId) -> StoreResult<Option<Node>> {
    let Some(node) = fetch_record::<Node>(txn, tables::NODES, "node", id.get())? else {
        return Ok(None);
    };
    if node.id != id {
        return Err(StoreError::NodeIdMismatch { id });
    }
    Ok(Some(node))
}

fn fetch_edge(txn: &redb::ReadTransaction, id: EdgeId) -> StoreResult<Option<Edge>> {
    let Some(edge) = fetch_record::<Edge>(txn, tables::EDGES, "edge", id.get())? else {
        return Ok(None);
    };
    if edge.id != id {
        return Err(StoreError::EdgeIdMismatch { id });
    }
    Ok(Some(edge))
}

/// Run a bounded range scan over `table_def` between `lo` and `hi`
/// inclusive, projecting every row through `extract`.
///
/// Centralising this loop is what lets the three "by-prefix" indexes
/// (kind-tag prefix, file-id prefix, endpoint+edge-kind prefix) share one
/// implementation despite their key tuples having different shapes — the
/// caller picks the projection, redb's `Key`/`Value` traits abstract the
/// rest.
fn scan_table<'a, K, V, R, F>(
    txn: &redb::ReadTransaction,
    table_def: TableDefinition<'static, K, V>,
    op: &'static str,
    bounds: (K::SelfType<'a>, K::SelfType<'a>),
    mut extract: F,
) -> StoreResult<Vec<R>>
where
    K: Key + 'static,
    V: Value + 'static,
    F: FnMut(K::SelfType<'_>, V::SelfType<'_>) -> R,
{
    let table = match txn.open_table(table_def) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::table(op, e)),
    };
    let (lo, hi) = bounds;
    let iter = table
        .range(lo..=hi)
        .map_err(|e| StoreError::storage(op, e))?;
    let mut out = Vec::new();
    for row in iter {
        let (key, value) = row.map_err(|e| StoreError::storage(op, e))?;
        out.push(extract(key.value(), value.value()));
    }
    Ok(out)
}

/// Collect node ids matching `(prefix_tag, *)` from a kind-tagged composite
/// index table such as `by_kind`.
fn collect_ids_by_u8_prefix(
    txn: &redb::ReadTransaction,
    table_def: TableDefinition<'static, (u8, u64), ()>,
    op: &'static str,
    prefix: u8,
) -> StoreResult<Vec<u64>> {
    scan_table(
        txn,
        table_def,
        op,
        ((prefix, u64::MIN), (prefix, u64::MAX)),
        |key, ()| key.1,
    )
}

/// Collect node ids matching `(prefix, *)` from a `(u64, u64) → ()` index
/// such as `by_file`.
fn collect_ids_by_u64_prefix(
    txn: &redb::ReadTransaction,
    table_def: TableDefinition<'static, (u64, u64), ()>,
    op: &'static str,
    prefix: u64,
) -> StoreResult<Vec<u64>> {
    scan_table(
        txn,
        table_def,
        op,
        ((prefix, u64::MIN), (prefix, u64::MAX)),
        |key, ()| key.1,
    )
}

/// Collect edge ids attached to `endpoint` with `kind_tag` from a
/// `(u64, u8, u64) → u64` endpoint-keyed index (`edges_out` / `edges_in`).
fn collect_edges_by_endpoint(
    txn: &redb::ReadTransaction,
    table_def: TableDefinition<'static, (u64, u8, u64), u64>,
    op: &'static str,
    endpoint: u64,
    kind_tag: u8,
) -> StoreResult<Vec<u64>> {
    scan_table(
        txn,
        table_def,
        op,
        (
            (endpoint, kind_tag, u64::MIN),
            (endpoint, kind_tag, u64::MAX),
        ),
        |_, value| value,
    )
}

/// Materialise nodes for the given ids, preserving order.
fn nodes_for_ids(txn: &redb::ReadTransaction, ids: Vec<u64>) -> Vec<StoreResult<Node>> {
    ids.into_iter()
        .map(|raw| fetch_node_required(txn, raw))
        .collect()
}

fn fetch_node_required(txn: &redb::ReadTransaction, raw: u64) -> StoreResult<Node> {
    let id = NodeId::new(raw);
    fetch_node(txn, id)?.ok_or_else(|| StoreError::Integrity {
        detail: format!("index pointed to missing node id={raw}"),
    })
}

/// Iterate every node of a given kind via the `by_kind` index.
pub(crate) fn nodes_of_kind(db: &redb::Database, kind: NodeKind) -> StoreResult<NodeIter> {
    let txn = db
        .begin_read()
        .map_err(|e| StoreError::txn("begin_read", e))?;
    let ids =
        collect_ids_by_u8_prefix(&txn, tables::BY_KIND, "by_kind.range", node_kind_tag(kind))?;
    Ok(nodes_for_ids(&txn, ids).into_iter())
}

/// Iterate every node attached to a given file via the `by_file` index.
pub(crate) fn nodes_in_file(db: &redb::Database, file: FileId) -> StoreResult<NodeIter> {
    let txn = db
        .begin_read()
        .map_err(|e| StoreError::txn("begin_read", e))?;
    let ids = collect_ids_by_u64_prefix(&txn, tables::BY_FILE, "by_file.range", file.raw())?;
    Ok(nodes_for_ids(&txn, ids).into_iter())
}

/// Materialise edges for the given ids, preserving order.
fn edges_for_ids(txn: &redb::ReadTransaction, ids: Vec<u64>) -> Vec<StoreResult<Edge>> {
    ids.into_iter()
        .map(|raw| fetch_edge_required(txn, raw))
        .collect()
}

fn fetch_edge_required(txn: &redb::ReadTransaction, raw: u64) -> StoreResult<Edge> {
    let id = EdgeId::new(raw);
    fetch_edge(txn, id)?.ok_or_else(|| StoreError::Integrity {
        detail: format!("index pointed to missing edge id={raw}"),
    })
}

/// Shared body for `outgoing_edges` / `incoming_edges`: open a read txn,
/// scan the chosen endpoint table for `(endpoint, kind, *)`, materialise
/// the resulting edges.
fn endpoint_edges(
    db: &redb::Database,
    table_def: TableDefinition<'static, (u64, u8, u64), u64>,
    op: &'static str,
    endpoint: NodeId,
    kind: EdgeKind,
) -> StoreResult<EdgeIter> {
    let txn = db
        .begin_read()
        .map_err(|e| StoreError::txn("begin_read", e))?;
    let ids = collect_edges_by_endpoint(&txn, table_def, op, endpoint.get(), edge_kind_tag(kind))?;
    Ok(edges_for_ids(&txn, ids).into_iter())
}

/// Outgoing edges from `from` of a given kind.
pub(crate) fn outgoing_edges(
    db: &redb::Database,
    from: NodeId,
    kind: EdgeKind,
) -> StoreResult<EdgeIter> {
    endpoint_edges(db, tables::EDGES_OUT, "edges_out.range", from, kind)
}

/// Incoming edges into `to` of a given kind.
pub(crate) fn incoming_edges(
    db: &redb::Database,
    to: NodeId,
    kind: EdgeKind,
) -> StoreResult<EdgeIter> {
    endpoint_edges(db, tables::EDGES_IN, "edges_in.range", to, kind)
}

/// Convenience: first AST_PARENT edge `child → parent`.
pub(crate) fn ast_parent(db: &redb::Database, child: NodeId) -> StoreResult<Option<NodeId>> {
    let mut iter = outgoing_edges(db, child, EdgeKind::AST_PARENT)?;
    match iter.next() {
        Some(Ok(edge)) => Ok(Some(edge.to)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Convenience: ids of every node whose AST_PARENT points at `parent`.
///
/// `clippy::needless_collect` is silenced because the public return type
/// [`NodeIdIter`] is the owned `IntoIter`; we materialise so the iterator
/// outlives the closing edge-iterator's transaction handle.
#[allow(clippy::needless_collect)]
pub(crate) fn ast_children(db: &redb::Database, parent: NodeId) -> StoreResult<NodeIdIter> {
    let edges = incoming_edges(db, parent, EdgeKind::AST_PARENT)?;
    let ids: Vec<StoreResult<NodeId>> = edges.map(|res| res.map(|edge| edge.from)).collect();
    Ok(ids.into_iter())
}
