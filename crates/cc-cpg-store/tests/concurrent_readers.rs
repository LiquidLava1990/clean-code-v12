//! Multiple reader threads + one writer thread see consistent snapshots.

mod common;

use std::thread;

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeKind, Value};
use cc_cpg_store::{CpgStore, FileId};
use common::TempStore;

const ROUNDS: usize = 10;
const PER_BATCH: u64 = 4;
const SEED_FUNCTIONS: u64 = 8;
const READERS: usize = 4;
const READS_PER_THREAD: usize = 50;

fn seed_store(store: &CpgStore) {
    let mut seed = CpgWriteBatch::new();
    for i in 0..SEED_FUNCTIONS {
        seed.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(format!("seed{i}"))),
        );
    }
    store.write_batch(FileId::new(1), seed).expect("seed");
}

fn spawn_reader(store: CpgStore) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last = 0usize;
        for _ in 0..READS_PER_THREAD {
            let count = store
                .nodes_of_kind(NodeKind::Function)
                .expect("range")
                .count();
            assert!(count >= last, "snapshot regressed: {count} < {last}");
            last = count;
        }
    })
}

fn spawn_writer(store: CpgStore) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for round in 0..ROUNDS as u64 {
            let mut batch = CpgWriteBatch::new();
            for i in 0..PER_BATCH {
                batch.push_node(
                    NodeBuilder::new(NodeKind::Function)
                        .with_prop("name", Value::String(format!("r{round}_{i}"))),
                );
            }
            store.write_batch(FileId::new(2), batch).expect("write");
            thread::yield_now();
        }
    })
}

#[test]
fn concurrent_readers_writer_consistent() {
    let temp = TempStore::fresh();
    seed_store(&temp.store);

    let mut handles: Vec<thread::JoinHandle<()>> = (0..READERS)
        .map(|_| spawn_reader(temp.store.clone()))
        .collect();
    handles.push(spawn_writer(temp.store.clone()));
    for h in handles {
        h.join().expect("thread");
    }

    let expected =
        usize::try_from(SEED_FUNCTIONS).unwrap() + ROUNDS * usize::try_from(PER_BATCH).unwrap();
    let final_count = temp
        .store
        .nodes_of_kind(NodeKind::Function)
        .expect("range")
        .count();
    assert_eq!(final_count, expected);
    drop(temp.dir);
}
