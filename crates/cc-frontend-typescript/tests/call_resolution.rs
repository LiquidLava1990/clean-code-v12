//! Integration tests for the TypeScript frontend's `CG_CALLS` / `REFERENCES`
//! post-passes.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_typescript::TypescriptFrontend;

fn lift(src: &str) -> CpgWriteBatch {
    let frontend = TypescriptFrontend::new();
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
    let src = "function callee() {}\nfunction caller() { callee(); }\n";
    let batch = lift(src);
    let callee_id = find_function(&batch, "callee");
    let any_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS && e.to == callee_id);
    assert!(any_edge, "expected CG_CALLS edge into `callee`");
}

#[test]
fn cg_calls_strips_qualified_callee() {
    let src = "\
class C {
  helper() {}
  caller() { this.helper(); }
}
";
    let batch = lift(src);
    let helper_id = find_function(&batch, "helper");
    let any_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS && e.to == helper_id);
    assert!(
        any_edge,
        "expected CG_CALLS edge to `helper` from `this.helper()`"
    );
}

#[test]
fn references_emitted_for_identifier_use() {
    // Passing a function reference as an argument exercises the default
    // resolver: the bare `helper` identifier inside the call args
    // resolves to the top-level function declaration.
    let src = "\
function helper() {}
function apply(fn: () => void) {}
function caller() { apply(helper); }
";
    let batch = lift(src);
    let any_ref = batch.edges().iter().any(|e| e.kind == EdgeKind::REFERENCES);
    assert!(any_ref, "expected at least one REFERENCES edge");
}

#[test]
fn unresolved_callee_emits_no_call_edge() {
    let src = "function f() { console.log('hi'); }\n";
    let batch = lift(src);
    // `console` and `log` are external — neither declared in this batch,
    // so no CG_CALLS edge is expected.
    let any_cg = batch.edges().iter().any(|e| e.kind == EdgeKind::CG_CALLS);
    assert!(
        !any_cg,
        "external callee `console.log` should not produce a CG_CALLS edge"
    );
}
