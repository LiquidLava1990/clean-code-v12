//! Hand-patching the on-disk schema version makes re-open fail with an
//! actionable [`StoreError::SchemaMismatch`].

mod common;

use cc_cpg_store::{CpgStore, StoreError};
use common::{sample_batch, TempStore};

/// Re-open a store after directly poking a different schema version into the
/// `meta` table. We do this by opening the underlying redb file ourselves;
/// no `unsafe`, no FFI — just two redb crates pointing at the same file.
fn corrupt_schema_version(path: &camino::Utf8Path, new_version: u32) {
    use redb::TableDefinition;
    let db = redb::Database::create(path.as_std_path()).expect("redb open");
    let txn = db.begin_write().expect("begin_write");
    {
        let table_def: TableDefinition<'static, &'static str, &'static [u8]> =
            TableDefinition::new("meta");
        let mut table = txn.open_table(table_def).expect("open meta");
        let bytes = bincode::serde::encode_to_vec(new_version, bincode::config::standard())
            .expect("encode");
        table
            .insert("schema_version", bytes.as_slice())
            .expect("insert");
    }
    txn.commit().expect("commit");
}

#[test]
fn schema_version_mismatch_rejected() {
    // Step 1: create a valid store (so meta + nodes tables exist).
    let temp = TempStore::fresh();
    let (batch, _, _) = sample_batch();
    temp.store
        .write_batch(cc_cpg_store::FileId::new(1), batch)
        .expect("write");
    let path = temp.path.clone();
    drop(temp.store);

    // Step 2: poke a bogus version.
    corrupt_schema_version(&path, 99);

    // Step 3: re-open returns SchemaMismatch with actionable message.
    let err = CpgStore::open(path).expect_err("must reject mismatched schema");
    let msg = format!("{err}");
    assert!(msg.contains("schema mismatch"), "what missing: {msg}");
    assert!(msg.contains("Fix:"), "how missing: {msg}");
    match err {
        StoreError::SchemaMismatch {
            found, expected, ..
        } => {
            assert_eq!(found, 99);
            assert_eq!(expected, cc_cpg::SCHEMA_VERSION);
        }
        other => panic!("expected SchemaMismatch, got {other:?}"),
    }
    drop(temp.dir); // keep the tempdir alive until the end
}
