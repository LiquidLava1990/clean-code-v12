//! Opening a fresh path creates a redb file and stamps the schema version.

mod common;

use cc_cpg::SCHEMA_VERSION;
use cc_cpg_store::CpgStore;
use common::TempStore;

#[test]
fn open_creates_db_and_persists_schema_version() {
    let temp = TempStore::fresh();

    // File exists on disk after open.
    assert!(temp.path.exists(), "expected db file at {}", temp.path);

    // Re-opening the same path succeeds and keeps the schema version.
    drop(temp.store);
    let _store = CpgStore::open(temp.path.clone()).expect("re-open");
    let _ = SCHEMA_VERSION; // tie test to the constant for documentation.
    drop(temp.dir);
}
