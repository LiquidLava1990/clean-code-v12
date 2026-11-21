//! Error type for the persistent CPG store.
//!
//! Every variant carries a short *what failed* message in its `#[error(...)]`
//! header and an *how to fix* hint embedded in the same string. Tests assert
//! both strings appear (see `tests/error_messages.rs`).
//!
//! All `StoreError`s are constructed via the helper constructors in this
//! module so every error gets the same actionable shape.

use camino::Utf8PathBuf;
use thiserror::Error;

use cc_cpg::{EdgeId, NodeId};

/// Convenience result alias used across the crate.
pub type StoreResult<T> = Result<T, StoreError>;

/// Errors emitted by the on-disk CPG store.
///
/// Every variant message is structured as `"<what>: <details>. Fix: <how>"`.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem-level failure opening or creating the database file.
    #[error(
        "could not open redb database at {path}: {source}. \
         Fix: check the parent directory exists, is writable, and the file is \
         not held open by another process."
    )]
    OpenFailed {
        /// Database path that failed to open.
        path: Utf8PathBuf,
        /// Underlying redb error.
        #[source]
        source: redb::DatabaseError,
    },

    /// Schema version recorded in `meta` does not match this binary.
    #[error(
        "schema mismatch in {path}: store has schema_version={found} but this \
         binary expects schema_version={expected}. \
         Fix: rebuild the CPG with `ccv12 check --rebuild` (caches are \
         invalidated whenever cc-cpg::SCHEMA_VERSION bumps)."
    )]
    SchemaMismatch {
        /// Database path.
        path: Utf8PathBuf,
        /// Version recorded in the store.
        found: u32,
        /// Version compiled into the current binary.
        expected: u32,
    },

    /// `meta["schema_version"]` row was missing from a non-empty store.
    #[error(
        "schema_version row missing in {path}. \
         Fix: this store was not initialised by cc-cpg-store >= 0.1; delete \
         the file and rebuild the CPG."
    )]
    SchemaUnset {
        /// Database path.
        path: Utf8PathBuf,
    },

    /// A redb transaction failed.
    #[error(
        "redb transaction failed during {op}: {source}. \
         Fix: retry once; if the failure persists the database file may be \
         corrupted — delete `<repo>/.cc/cpg.redb` and rebuild."
    )]
    Transaction {
        /// Logical operation name (e.g. `"begin_write"`).
        op: &'static str,
        /// Underlying redb error.
        #[source]
        source: redb::TransactionError,
    },

    /// A redb table operation failed.
    #[error(
        "redb table operation `{op}` failed: {source}. \
         Fix: this almost always means schema drift between writer and \
         reader — rebuild the CPG with `ccv12 check --rebuild`."
    )]
    Table {
        /// Logical operation name.
        op: &'static str,
        /// Underlying redb error.
        #[source]
        source: redb::TableError,
    },

    /// A row-level read/write inside redb failed.
    #[error(
        "redb storage I/O failed during {op}: {source}. \
         Fix: ensure the disk has space and the database file is not on a \
         network filesystem (redb requires local-disk semantics)."
    )]
    Storage {
        /// Logical operation name.
        op: &'static str,
        /// Underlying redb error.
        #[source]
        source: redb::StorageError,
    },

    /// Commit of a write transaction failed.
    #[error(
        "redb commit failed: {source}. \
         Fix: the in-memory writes were rolled back; retry the operation. If \
         it keeps failing, check disk space and filesystem health."
    )]
    Commit {
        /// Underlying redb error.
        #[source]
        source: redb::CommitError,
    },

    /// Compaction failed.
    #[error(
        "redb compaction failed: {source}. \
         Fix: ensure no other handles are holding read transactions and that \
         the disk has free space (compaction temporarily doubles file size)."
    )]
    Compaction {
        /// Underlying redb error.
        #[source]
        source: redb::CompactionError,
    },

    /// bincode encode failure (should be unreachable for well-formed data).
    #[error(
        "bincode encode failed for {what}: {source}. \
         Fix: this indicates a bug in cc-cpg's serde derive — file an issue \
         with the offending node/edge id."
    )]
    Encode {
        /// What was being encoded (e.g. `"node"`, `"edge"`).
        what: &'static str,
        /// Underlying bincode error.
        #[source]
        source: bincode::error::EncodeError,
    },

    /// bincode decode failure — typically schema drift.
    #[error(
        "bincode decode failed for {what}: {source}. \
         Fix: schema drift between writer and reader; rebuild the CPG with \
         `ccv12 check --rebuild`."
    )]
    Decode {
        /// What was being decoded.
        what: &'static str,
        /// Underlying bincode error.
        #[source]
        source: bincode::error::DecodeError,
    },

    /// A foreign-key style integrity check failed (e.g. dangling edge).
    #[error(
        "graph integrity violation: {detail}. \
         Fix: this is a bug in the frontend that produced the batch — every \
         edge endpoint must be a node pushed in the same batch."
    )]
    Integrity {
        /// Human-readable detail.
        detail: String,
    },

    /// Tried to look up a node by id and the encoded value was malformed.
    #[error(
        "node {id:?} stored at the wrong key (decoded id mismatch). \
         Fix: rebuild the CPG; the on-disk file is inconsistent."
    )]
    NodeIdMismatch {
        /// Id requested.
        id: NodeId,
    },

    /// Tried to look up an edge by id and the encoded value was malformed.
    #[error(
        "edge {id:?} stored at the wrong key (decoded id mismatch). \
         Fix: rebuild the CPG; the on-disk file is inconsistent."
    )]
    EdgeIdMismatch {
        /// Id requested.
        id: EdgeId,
    },
}

impl StoreError {
    /// Wrap an `OpenFailed` with the offending path.
    pub(crate) const fn open(path: Utf8PathBuf, source: redb::DatabaseError) -> Self {
        Self::OpenFailed { path, source }
    }

    /// Wrap a `Transaction` error with a logical op label.
    pub(crate) const fn txn(op: &'static str, source: redb::TransactionError) -> Self {
        Self::Transaction { op, source }
    }

    /// Wrap a `Table` error with a logical op label.
    pub(crate) const fn table(op: &'static str, source: redb::TableError) -> Self {
        Self::Table { op, source }
    }

    /// Wrap a `Storage` error with a logical op label.
    pub(crate) const fn storage(op: &'static str, source: redb::StorageError) -> Self {
        Self::Storage { op, source }
    }

    /// Wrap a `Commit` error.
    pub(crate) const fn commit(source: redb::CommitError) -> Self {
        Self::Commit { source }
    }

    /// Wrap a bincode encode error.
    pub(crate) const fn encode(what: &'static str, source: bincode::error::EncodeError) -> Self {
        Self::Encode { what, source }
    }

    /// Wrap a bincode decode error.
    pub(crate) const fn decode(what: &'static str, source: bincode::error::DecodeError) -> Self {
        Self::Decode { what, source }
    }
}
