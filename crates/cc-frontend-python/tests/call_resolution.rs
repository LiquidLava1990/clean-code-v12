//! Integration tests for the Python frontend's `CG_CALLS` / `REFERENCES`
//! post-passes.
//!
//! These run end-to-end through `LanguageFrontend::lift`, which the
//! frontend wires to the shared resolvers, so any caller of
//! `frontend.lift(...)` automatically gets the resolved batch.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_python::PythonFrontend;

/// Helper: parse + lift, returning the populated batch.
fn lift(src: &str) -> CpgWriteBatch {
    let frontend = PythonFrontend::new();
    let tree = frontend.parse(src).expect("parse");
    let mut batch = CpgWriteBatch::new();
    frontend
        .lift(&tree, src, &mut batch, FileId::new(1))
        .expect("lift");
    batch
}

/// Borrow a `String`-typed property.
fn string_prop<'a>(node: &'a cc_cpg::Node, key: &str) -> Option<&'a str> {
    node.prop(key).and_then(Value::as_str)
}

/// Find the first `Function` node with the given `name` property.
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
    // `caller` calls `callee` — both top-level. We expect at least one
    // CG_CALLS edge whose `to` is the callee Function id.
    let src = "def callee():\n    pass\n\ndef caller():\n    callee()\n";
    let batch = lift(src);
    let callee_id = find_function(&batch, "callee");

    let cg_to_callee: Vec<_> = batch
        .edges()
        .iter()
        .filter(|e| e.kind == EdgeKind::CG_CALLS && e.to == callee_id)
        .collect();
    assert!(
        !cg_to_callee.is_empty(),
        "expected at least one CG_CALLS edge into `callee`"
    );
}

#[test]
fn cg_calls_strips_qualified_callee() {
    // `self.helper()` should still resolve to the `helper` Method
    // declaration on the same class via the dot-strip.
    let src = "\
class C:
    def helper(self):
        pass

    def caller(self):
        self.helper()
";
    let batch = lift(src);
    let helper_id = find_function(&batch, "helper");
    let any_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS && e.to == helper_id);
    assert!(
        any_edge,
        "expected CG_CALLS edge to `helper` from a `self.helper()` call"
    );
}

#[test]
fn references_emitted_for_identifier_use() {
    // Pass `helper` as an argument to `apply` — the bare `helper`
    // identifier inside the call's argument list should resolve to the
    // top-level Function, producing one REFERENCES edge.
    let src = "\
def helper():
    pass

def apply(fn):
    pass

def caller():
    apply(helper)
";
    let batch = lift(src);
    let any_ref = batch.edges().iter().any(|e| e.kind == EdgeKind::REFERENCES);
    assert!(any_ref, "expected at least one REFERENCES edge");
}

#[test]
fn unresolved_callee_emits_no_call_edge() {
    // `print` isn't defined in this file; the resolver should NOT invent
    // a CG_CALLS edge for it (over-approximation is per-batch only).
    let src = "def f():\n    print(\"hi\")\n";
    let batch = lift(src);
    let any_cg = batch.edges().iter().any(|e| e.kind == EdgeKind::CG_CALLS);
    assert!(
        !any_cg,
        "no in-batch declaration of `print` -> no CG_CALLS edge expected"
    );
}
