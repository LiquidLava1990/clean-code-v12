//! Integration tests for the Go frontend's `CG_CALLS` / `REFERENCES`
//! post-passes.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_go::GoFrontend;

fn lift(src: &str) -> CpgWriteBatch {
    let frontend = GoFrontend::new();
    let tree = frontend.parse(src).expect("parse");
    let mut batch = CpgWriteBatch::new();
    frontend
        .lift(&tree, src, &mut batch, FileId::new(1))
        .expect("lift");
    batch
}

fn string_prop<'a>(node: &'a cc_cpg::Node, key: &str) -> Option<&'a str> {
    node.prop(key).and_then(Value::as_str)
}

fn find_function(batch: &CpgWriteBatch, name: &str) -> cc_cpg::NodeId {
    batch
        .nodes()
        .iter()
        .find(|n| {
            matches!(n.kind, NodeKind::Function | NodeKind::Method)
                && string_prop(n, "name") == Some(name)
        })
        .unwrap_or_else(|| panic!("no function named {name}"))
        .id
}

#[test]
fn cg_calls_emitted_for_local_call() {
    let src = "\
package main

func callee() {}

func caller() {
    callee()
}
";
    let batch = lift(src);
    let callee_id = find_function(&batch, "callee");
    let any_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS && e.to == callee_id);
    assert!(any_edge, "expected CG_CALLS edge into `callee`");
}

#[test]
fn cg_calls_strips_receiver_prefix() {
    // Method-value-style call with a receiver prefix (`recv.method`)
    // should still resolve via the dot-strip.
    let src = "\
package main

type T struct{}

func (t T) Helper() {}

func (t T) Caller() {
    t.Helper()
}
";
    let batch = lift(src);
    let helper_id = find_function(&batch, "Helper");
    let any_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS && e.to == helper_id);
    assert!(
        any_edge,
        "expected CG_CALLS edge to `Helper` from `t.Helper()`"
    );
}

#[test]
fn references_emitted_for_identifier_use() {
    // Pass a function value as an argument to exercise the default
    // resolver — the bare `helper` identifier in the call args should
    // resolve to the top-level function declaration.
    let src = "\
package main

func helper() {}

func apply(fn func()) {}

func caller() {
    apply(helper)
}
";
    let batch = lift(src);
    let any_ref = batch.edges().iter().any(|e| e.kind == EdgeKind::REFERENCES);
    assert!(any_ref, "expected at least one REFERENCES edge");
}

#[test]
fn unresolved_callee_emits_no_call_edge() {
    let src = "\
package main

import \"fmt\"

func f() {
    fmt.Println(\"hi\")
}
";
    let batch = lift(src);
    let any_cg = batch.edges().iter().any(|e| e.kind == EdgeKind::CG_CALLS);
    assert!(
        !any_cg,
        "external callee `fmt.Println` should not produce a CG_CALLS edge"
    );
}
