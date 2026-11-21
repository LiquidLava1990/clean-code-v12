//! `meta` table helpers — schema-version handshake + path↔FileId mapping.
//!
//! The `meta` table is a simple `&str → bincode(value)` key-value store. Two
//! conventions are used:
//!
//! - `"schema_version"` → `u32`
//! - `"path:<utf8 path>"` → `u64` (FileId)
//!
//! Splitting the path map into per-key rows (rather than one big bincode blob)
//! means concurrent writers can grow the map without read-modify-write hazards
//! on a hot row.
//!
//! All public read/write helpers in this module funnel through the private
//! `read_meta` / `write_meta` generics so that "open meta, get/insert, decode"
//! lives in exactly one place. This stops new meta keys (paths, counters,
//! settings) from spawning yet another copy-pasted sibling.

use camino::Utf8Path;
use cc_frontend::FileId;
use redb::{ReadableTable, ReadableTableMetadata};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use crate::codec;
use crate::error::{StoreError, StoreResult};
use crate::tables;

/// Key under which the `u32` schema version lives.
pub(crate) const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Key under which the next-free `NodeId` high-water mark lives.
pub(crate) const NEXT_NODE_ID_KEY: &str = "next_node_id";

/// Key under which the next-free `EdgeId` high-water mark lives.
pub(crate) const NEXT_EDGE_ID_KEY: &str = "next_edge_id";

/// Look up `key` in any already-open meta table (works for both read- and
/// write-transaction-backed tables since both implement `ReadableTable`).
///
/// Centralises the `get → decode` pair so the read-transaction and
/// write-transaction call sites stop duplicating the same five lines.
fn lookup_decoded<T, R>(table: &R, key: &str, what: &'static str) -> StoreResult<Option<T>>
where
    T: DeserializeOwned,
    R: ReadableTable<&'static str, &'static [u8]>,
{
    let Some(row) = table.get(key).map_err(|e| StoreError::storage(what, e))? else {
        return Ok(None);
    };
    let value = codec::decode::<T>(what, row.value())?;
    Ok(Some(value))
}

/// Read a bincode-encoded value out of the `meta` table under `key` from a
/// read transaction.
///
/// Returns `Ok(None)` either when the table itself has not been materialised
/// yet (a fresh-open store) or when the key is absent. Callers that need to
/// distinguish those two cases must use `is_empty_store` first.
fn read_meta<T: DeserializeOwned>(
    txn: &redb::ReadTransaction,
    key: &str,
    what: &'static str,
) -> StoreResult<Option<T>> {
    let table = match txn.open_table(tables::META) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(StoreError::table("open meta", e)),
    };
    lookup_decoded(&table, key, what)
}

/// Encode `value` and `insert` it into the `meta` table under `key`.
///
/// Same labelling contract as `read_meta` — a single `what` is used for both
/// the encode error (if bincode rejects the value) and the redb storage
/// error (if the row write fails).
fn write_meta<T: Serialize>(
    txn: &redb::WriteTransaction,
    key: &str,
    what: &'static str,
    value: &T,
) -> StoreResult<()> {
    let mut table = txn
        .open_table(tables::META)
        .map_err(|e| StoreError::table("open meta", e))?;
    let bytes = codec::encode(what, value)?;
    table
        .insert(key, bytes.as_slice())
        .map_err(|e| StoreError::storage("meta.insert", e))?;
    Ok(())
}

/// Read the recorded schema version, returning `None` if the row is absent.
///
/// # Errors
///
/// Returns [`StoreError::Storage`] / [`StoreError::Decode`] on redb or
/// bincode failure.
pub(crate) fn read_schema_version(txn: &redb::ReadTransaction) -> StoreResult<Option<u32>> {
    read_meta::<u32>(txn, SCHEMA_VERSION_KEY, "schema_version")
}

/// Write the given schema version into the `meta` table.
pub(crate) fn write_schema_version(txn: &redb::WriteTransaction, version: u32) -> StoreResult<()> {
    write_meta(txn, SCHEMA_VERSION_KEY, "schema_version", &version)
}

/// Read a `u64` counter from the meta table, defaulting to `default` when
/// the row is absent.
///
/// Counters are read inside a write transaction (the writer holds the redb
/// write lock for the whole `read counter → mutate → write counter` cycle),
/// so the `meta` table is guaranteed to exist by the time we get here —
/// table-open errors are therefore surfaced as `StoreError::Table`, not
/// silently swallowed as `default`.
pub(crate) fn read_counter(
    txn: &redb::WriteTransaction,
    key: &'static str,
    default: u64,
) -> StoreResult<u64> {
    let table = txn
        .open_table(tables::META)
        .map_err(|e| StoreError::table("open meta", e))?;
    Ok(lookup_decoded::<u64, _>(&table, key, "counter")?.unwrap_or(default))
}

/// Persist a `u64` counter back into the meta table.
pub(crate) fn write_counter(
    txn: &redb::WriteTransaction,
    key: &'static str,
    value: u64,
) -> StoreResult<()> {
    write_meta(txn, key, "counter", &value)
}

/// Detect whether the underlying file already contains user data.
///
/// We treat *any* row in `nodes`/`edges` as "non-empty"; the schema-version
/// handshake refuses to silently overwrite a populated store.
pub(crate) fn is_empty_store(txn: &redb::ReadTransaction) -> StoreResult<bool> {
    for tname in [tables::NODES, tables::EDGES] {
        match txn.open_table(tname) {
            Ok(t) => {
                let len = t
                    .len()
                    .map_err(|e| StoreError::storage("meta.len(table)", e))?;
                if len > 0 {
                    return Ok(false);
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(StoreError::table("open table", e)),
        }
    }
    Ok(true)
}

/// Compose the `path:<...>` meta key for a given UTF-8 path.
fn path_key(path: &Utf8Path) -> String {
    format!("path:{path}")
}

/// Look up the FileId previously recorded for `path`, if any.
pub(crate) fn read_file_id(
    txn: &redb::ReadTransaction,
    path: &Utf8Path,
) -> StoreResult<Option<FileId>> {
    let key = path_key(path);
    let raw = read_meta::<u64>(txn, key.as_str(), "file_id")?;
    Ok(raw.map(FileId::new))
}

/// Persist the assignment `path → file_id`.
pub(crate) fn write_file_id(
    txn: &redb::WriteTransaction,
    path: &Utf8Path,
    file_id: FileId,
) -> StoreResult<()> {
    let key = path_key(path);
    write_meta(txn, key.as_str(), "file_id", &file_id.raw())
}

/// Compute a deterministic FileId from a path.
///
/// Truncates SHA-256 to its leading 8 bytes and reads them as little-endian.
/// Collisions are astronomically unlikely within one repo (≤ 2³² files); a
/// future Phase 1.5 wave can swap to full 16-byte ids if needed without a
/// schema bump (the on-disk type is already `u64`).
#[must_use]
pub(crate) fn deterministic_file_id(path: &Utf8Path) -> FileId {
    let mut hasher = Sha256::new();
    hasher.update(path.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[..8]);
    FileId::new(u64::from_le_bytes(buf))
}

/// Idempotent allocator: reuse an existing FileId if recorded, otherwise
/// derive one and persist it.
pub(crate) fn get_or_assign_file_id(db: &redb::Database, path: &Utf8Path) -> StoreResult<FileId> {
    {
        let read = db
            .begin_read()
            .map_err(|e| StoreError::txn("begin_read", e))?;
        if let Some(existing) = read_file_id(&read, path)? {
            return Ok(existing);
        }
    }
    let assigned = deterministic_file_id(path);
    let write = db
        .begin_write()
        .map_err(|e| StoreError::txn("begin_write", e))?;
    write_file_id(&write, path, assigned)?;
    write.commit().map_err(StoreError::commit)?;
    Ok(assigned)
}
