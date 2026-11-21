//! `file_id_for_path` is deterministic across opens for the same path and
//! distinct between different paths.

mod common;

use camino::Utf8PathBuf;
use cc_cpg_store::CpgStore;
use common::TempStore;

#[test]
fn file_id_deterministic_across_opens() {
    // NOTE: bind the whole TempStore, not destructured fields — the
    // `TempDir` inside it must outlive the second open.
    let temp = TempStore::fresh();
    let p = Utf8PathBuf::from("src/lib.rs");
    let id1 = temp.store.file_id_for_path(&p).expect("assign");
    let id2 = temp.store.file_id_for_path(&p).expect("reuse");
    assert_eq!(id1, id2, "same path must reuse same id");

    let path = temp.path.clone();
    drop(temp.store); // release the file handle
    let store2 = CpgStore::open(path).expect("re-open");
    let id3 = store2.file_id_for_path(&p).expect("after reopen");
    assert_eq!(id1, id3, "id must persist across re-open");
    drop(store2);
    drop(temp.dir); // explicit cleanup so the assertion above sees the file
}

#[test]
fn file_id_distinct_paths_distinct_ids() {
    let TempStore { store, .. } = TempStore::fresh();
    let a = store
        .file_id_for_path(&Utf8PathBuf::from("a.py"))
        .expect("a");
    let b = store
        .file_id_for_path(&Utf8PathBuf::from("b.py"))
        .expect("b");
    assert_ne!(a, b);
}
