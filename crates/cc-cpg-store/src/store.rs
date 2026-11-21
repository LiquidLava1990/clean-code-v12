//! [`CpgStore`] — public façade over the redb database.
//!
//! # Concurrency
//!
//! `CpgStore` is `Send + Sync`. redb's MVCC allows any number of concurrent
//! readers alongside a single writer. The store does *not* wrap the database
//! in a `Mutex` because doing so would defeat that property; instead, every
//! query opens its own short-lived `ReadTransaction` (so a writer can land
//! between two reads from the same logical client).
//!
//! # Lifecycle
//!
//! - [`CpgStore::open`] — open or create a database; performs the
//!   schema-version handshake.
//! - [`CpgStore::write_batch`] — atomically insert one
//!   [`cc_cpg::CpgWriteBatch`].
//! - read methods on `CpgStore` — all snapshot-consistent.
//! - [`CpgStore::compact`] — manual compaction trigger for Phase 4
//!   maintenance.

use std::sync::Arc;

use camino::{Utf8Path, Utf8PathBuf};
use cc_cpg::{CpgWriteBatch, Edge, EdgeId, EdgeKind, Node, NodeId, NodeKind, SCHEMA_VERSION};
use cc_frontend::FileId;

use crate::error::{StoreError, StoreResult};
use crate::read::{EdgeIter, NodeIdIter, NodeIter};
use crate::write::WriteSummary;
use crate::{meta, read, write};

/// Persistent CPG store backed by a single redb file.
///
/// Cloning the store is cheap (`Arc<Database>`) and produces a handle that
/// shares the same underlying database — multiple clones can read in
/// parallel.
#[derive(Clone)]
pub struct CpgStore {
    db: Arc<redb::Database>,
    path: Utf8PathBuf,
}

impl std::fmt::Debug for CpgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpgStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl CpgStore {
    /// Open or create a CPG store at `path`.
    ///
    /// On a fresh path the file is created and stamped with
    /// [`cc_cpg::SCHEMA_VERSION`]. On an existing path the schema version is
    /// validated against the binary's expectation; mismatch returns
    /// [`StoreError::SchemaMismatch`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OpenFailed`] on filesystem failure,
    /// [`StoreError::SchemaMismatch`] when the on-disk version differs, or
    /// [`StoreError::SchemaUnset`] when an existing populated file has no
    /// schema-version row.
    pub fn open(path: impl Into<Utf8PathBuf>) -> StoreResult<Self> {
        let path = path.into();
        let db = redb::Database::create(path.as_std_path())
            .map_err(|e| StoreError::open(path.clone(), e))?;
        let store = Self {
            db: Arc::new(db),
            path,
        };
        store.handshake_schema()?;
        Ok(store)
    }

    /// Path the store was opened against. Useful for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    fn handshake_schema(&self) -> StoreResult<()> {
        let outcome = self.read_schema_outcome()?;
        match outcome {
            SchemaOutcome::Match => Ok(()),
            SchemaOutcome::Mismatch(found) => Err(StoreError::SchemaMismatch {
                path: self.path.clone(),
                found,
                expected: SCHEMA_VERSION,
            }),
            SchemaOutcome::FreshStore => self.stamp_fresh_schema(),
            SchemaOutcome::PopulatedButUnset => Err(StoreError::SchemaUnset {
                path: self.path.clone(),
            }),
        }
    }

    fn read_schema_outcome(&self) -> StoreResult<SchemaOutcome> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::txn("begin_read", e))?;
        if let Some(v) = meta::read_schema_version(&read_txn)? {
            return Ok(if v == SCHEMA_VERSION {
                SchemaOutcome::Match
            } else {
                SchemaOutcome::Mismatch(v)
            });
        }
        if meta::is_empty_store(&read_txn)? {
            Ok(SchemaOutcome::FreshStore)
        } else {
            Ok(SchemaOutcome::PopulatedButUnset)
        }
    }

    fn stamp_fresh_schema(&self) -> StoreResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::txn("begin_write", e))?;
        meta::write_schema_version(&write_txn, SCHEMA_VERSION)?;
        write_txn.commit().map_err(StoreError::commit)?;
        Ok(())
    }

    /// Insert one finished batch.
    ///
    /// `file_id` is stamped into every node's row in the `by_file` index so
    /// per-file invalidation is later O(N).
    ///
    /// # Errors
    ///
    /// Returns transaction / encode / storage errors from the underlying
    /// redb call chain. Either the entire batch lands or none of it does.
    pub fn write_batch(&self, file_id: FileId, batch: CpgWriteBatch) -> StoreResult<WriteSummary> {
        write::write_batch(&self.db, file_id, batch)
    }

    /// Fetch one node by id.
    ///
    /// # Errors
    ///
    /// See [`StoreError`] — typically [`StoreError::Storage`] on read.
    pub fn node(&self, id: NodeId) -> StoreResult<Option<Node>> {
        read::node(&self.db, id)
    }

    /// Fetch one edge by id.
    ///
    /// # Errors
    ///
    /// See [`StoreError`].
    pub fn edge(&self, id: EdgeId) -> StoreResult<Option<Edge>> {
        read::edge(&self.db, id)
    }

    /// Iterate every node of a given kind.
    ///
    /// Results are materialised eagerly into a `Vec` so the iterator owns
    /// its data and the caller doesn't have to thread a transaction
    /// lifetime.
    ///
    /// # Errors
    ///
    /// Returns errors at iterator-construction time; per-item errors are
    /// also possible (e.g. an index row pointing at a missing node).
    pub fn nodes_of_kind(&self, kind: NodeKind) -> StoreResult<NodeIter> {
        read::nodes_of_kind(&self.db, kind)
    }

    /// Iterate every node attached to a given file.
    ///
    /// # Errors
    ///
    /// As [`Self::nodes_of_kind`].
    pub fn nodes_in_file(&self, file: FileId) -> StoreResult<NodeIter> {
        read::nodes_in_file(&self.db, file)
    }

    /// Outgoing edges from `from` of a given `kind`.
    ///
    /// # Errors
    ///
    /// As [`Self::nodes_of_kind`].
    pub fn outgoing_edges(&self, from: NodeId, kind: EdgeKind) -> StoreResult<EdgeIter> {
        read::outgoing_edges(&self.db, from, kind)
    }

    /// Incoming edges into `to` of a given `kind`.
    ///
    /// # Errors
    ///
    /// As [`Self::nodes_of_kind`].
    pub fn incoming_edges(&self, to: NodeId, kind: EdgeKind) -> StoreResult<EdgeIter> {
        read::incoming_edges(&self.db, to, kind)
    }

    /// First AST_PARENT target for `child`.
    ///
    /// Convenience over `outgoing_edges(_, AST_PARENT).next()`.
    ///
    /// # Errors
    ///
    /// As [`Self::nodes_of_kind`].
    pub fn ast_parent(&self, child: NodeId) -> StoreResult<Option<NodeId>> {
        read::ast_parent(&self.db, child)
    }

    /// Ids of every direct AST child of `parent`.
    ///
    /// # Errors
    ///
    /// As [`Self::nodes_of_kind`].
    pub fn ast_children(&self, parent: NodeId) -> StoreResult<NodeIdIter> {
        read::ast_children(&self.db, parent)
    }

    /// Resolve `path` to a stable, deterministic [`FileId`].
    ///
    /// First call for a given path computes
    /// `u64::from_le_bytes(sha256(path)[..8])` and persists it; subsequent
    /// calls return the recorded id.
    ///
    /// # Errors
    ///
    /// Returns redb / encode errors from the meta-table write.
    pub fn file_id_for_path(&self, path: &Utf8Path) -> StoreResult<FileId> {
        meta::get_or_assign_file_id(&self.db, path)
    }

    /// Run redb's compaction routine.
    ///
    /// Requires exclusive access; concurrent readers/writers will block until
    /// compaction finishes.
    ///
    /// # Errors
    ///
    /// Returns the underlying redb compaction error wrapped in
    /// [`StoreError::Storage`].
    pub fn compact(&mut self) -> StoreResult<bool> {
        // `Database::compact` requires `&mut Database`. We try to take
        // exclusive ownership through the Arc; if other clones still hold
        // the database we surface that as an integrity error so the caller
        // can drop their handles and retry.
        let db = Arc::get_mut(&mut self.db).ok_or_else(|| StoreError::Integrity {
            detail: "cannot compact while other CpgStore clones hold the database — \
                     drop them first or run compact() in a single-handle context"
                .to_owned(),
        })?;
        db.compact()
            .map_err(|source| StoreError::Compaction { source })
    }
}

/// Internal classification produced by the schema-version handshake.
enum SchemaOutcome {
    Match,
    Mismatch(u32),
    FreshStore,
    PopulatedButUnset,
}

// CpgStore is Send + Sync because Arc<Database> is Send + Sync.
// (redb::Database is Send + Sync as documented.)
const _: fn() = || {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CpgStore>();
};
