//! End-to-end smoke tests for `cc-fingerprint`.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeKind, Value};
use cc_fingerprint::{FingerprintBuilder, NamingStyle};

fn batch_with_function(name: &str) -> CpgWriteBatch {
    let mut batch = CpgWriteBatch::new();
    batch.push_node(
        NodeBuilder::new(NodeKind::Function).with_prop("name", Value::String(name.to_owned())),
    );
    batch
}

#[test]
fn dominant_naming_after_three_batches() {
    let mut b = FingerprintBuilder::new();
    // Two snake_case + one camel — feed them as separate "files".
    for name in ["alpha_one", "beta_two"] {
        let batch = batch_with_function(name);
        b.add_file(&batch, "py").expect("add_file ok");
    }
    let mixed = batch_with_function("camelOne");
    b.add_file(&mixed, "py").expect("add_file ok");

    // Below 10-sample floor — no dominant yet.
    let snapshot = b.finalize();
    assert_eq!(snapshot.dominant_naming(NodeKind::Function), None);
    assert_eq!(snapshot.sample_size.files, 3);
    assert_eq!(snapshot.sample_size.identifiers, 3);
}

#[test]
fn outlier_detected_when_dominant_clear() {
    let mut b = FingerprintBuilder::new();
    for i in 0..9 {
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(format!("snake_{i}"))),
        );
        b.add_file(&batch, "py").expect("ok");
    }
    let mut camel_batch = CpgWriteBatch::new();
    camel_batch.push_node(
        NodeBuilder::new(NodeKind::Function).with_prop("name", Value::String("myFn".into())),
    );
    b.add_file(&camel_batch, "py").expect("ok");

    let fp = b.finalize();
    assert_eq!(
        fp.dominant_naming(NodeKind::Function),
        Some(NamingStyle::SnakeCase)
    );
    assert!(fp.is_naming_outlier(NodeKind::Function, "myFn"));
    assert!(!fp.is_naming_outlier(NodeKind::Function, "my_fn"));
}

#[test]
fn no_dominance_means_no_outlier() {
    let mut b = FingerprintBuilder::new();
    for i in 0..5 {
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(format!("snake_{i}"))),
        );
        batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(format!("camelCase{i}"))),
        );
        b.add_file(&batch, "py").expect("ok");
    }
    let fp = b.finalize();
    assert_eq!(fp.dominant_naming(NodeKind::Function), None);
    assert!(!fp.is_naming_outlier(NodeKind::Function, "myFn"));
    assert!(!fp.is_naming_outlier(NodeKind::Function, "my_fn"));
}

#[test]
fn layering_chain_a_b_c_no_back_edge() {
    let mut b = FingerprintBuilder::new();

    // Module A imports B.
    let mut batch_a = CpgWriteBatch::new();
    batch_a
        .push_node(NodeBuilder::new(NodeKind::Module).with_prop("name", Value::String("A".into())));
    batch_a.push_node(
        NodeBuilder::new(NodeKind::Import).with_prop("source", Value::String("B".into())),
    );
    b.add_file(&batch_a, "py").expect("ok");

    // Module B imports C.
    let mut batch_b = CpgWriteBatch::new();
    batch_b
        .push_node(NodeBuilder::new(NodeKind::Module).with_prop("name", Value::String("B".into())));
    batch_b.push_node(
        NodeBuilder::new(NodeKind::Import).with_prop("source", Value::String("C".into())),
    );
    b.add_file(&batch_b, "py").expect("ok");

    let fp = b.finalize();
    assert!(fp.layering.is_downward_only("A", "B"));
    assert!(fp.layering.is_downward_only("A", "C"));
    // C importing A would close A -> B -> C -> A.
    assert!(!fp.layering.is_downward_only("C", "A"));
}

#[test]
fn errors_collected_from_try_and_raises() {
    let mut b = FingerprintBuilder::new();
    let mut batch = CpgWriteBatch::new();
    let module = batch.push_node(
        NodeBuilder::new(NodeKind::Module).with_prop("name", Value::String("svc".into())),
    );
    let _ = module;

    let func = batch.push_node(
        NodeBuilder::new(NodeKind::Function).with_prop("name", Value::String("do_thing".into())),
    );
    let raise_ty = batch.push_node(
        NodeBuilder::new(NodeKind::Type).with_prop("name", Value::String("RuntimeError".into())),
    );
    batch
        .push_edge(EdgeKind::RAISES, func, raise_ty)
        .expect("ok");

    let catch_ty = batch.push_node(
        NodeBuilder::new(NodeKind::Type).with_prop("name", Value::String("ValueError".into())),
    );
    batch.push_node(
        NodeBuilder::new(NodeKind::Try).with_prop("catches", Value::NodeList(vec![catch_ty])),
    );

    b.add_file(&batch, "py").expect("ok");
    let fp = b.finalize();

    let known: std::collections::HashSet<&str> = fp.known_errors().collect();
    assert!(known.contains("RuntimeError"));
    assert!(known.contains("ValueError"));
}
