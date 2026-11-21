//! Integration tests: every Function / Method / Class node the Go
//! frontend lifts must carry `is_pub` / `is_export` / `visibility` props.

use cc_cpg::{CpgWriteBatch, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_go::GoFrontend;

fn lift(source: &str) -> CpgWriteBatch {
    let frontend = GoFrontend::new();
    let tree = frontend.parse(source).expect("parse");
    let mut batch = CpgWriteBatch::new();
    frontend
        .lift(&tree, source, &mut batch, FileId::new(1))
        .expect("lift");
    batch
}

fn vis_props(batch: &CpgWriteBatch, kind: NodeKind, name: &str) -> (bool, bool, String) {
    for node in batch.nodes().iter() {
        if node.kind != kind {
            continue;
        }
        let matches_name = node
            .props
            .iter()
            .any(|(k, v)| k == "name" && matches!(v, Value::String(s) if s == name));
        if !matches_name {
            continue;
        }
        let mut is_pub = false;
        let mut is_export = false;
        let mut label = String::new();
        for (k, v) in &node.props {
            match (k.as_str(), v) {
                ("is_pub", Value::Bool(b)) => is_pub = *b,
                ("is_export", Value::Bool(b)) => is_export = *b,
                ("visibility", Value::String(s)) => label = s.clone(),
                _ => {}
            }
        }
        return (is_pub, is_export, label);
    }
    panic!("no {kind:?} node named {name}");
}

#[test]
fn go_capital_function_is_exported() {
    let batch = lift("package p\nfunc Alpha() {}\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "Alpha");
    assert!(is_pub);
    assert_eq!(label, "exported");
}

#[test]
fn go_lowercase_function_is_package() {
    let batch = lift("package p\nfunc beta() {}\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "beta");
    assert!(!is_pub);
    assert_eq!(label, "package");
}

#[test]
fn go_capital_struct_is_exported() {
    let batch = lift("package p\ntype Gamma struct{}\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Gamma");
    assert!(is_pub);
    assert_eq!(label, "exported");
}

#[test]
fn go_lowercase_struct_is_package() {
    let batch = lift("package p\ntype delta struct{}\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "delta");
    assert!(!is_pub);
    assert_eq!(label, "package");
}

#[test]
fn go_capital_method_is_exported() {
    let src = "package p\ntype S struct{}\nfunc (s *S) Epsilon() {}\nfunc (s *S) zeta() {}\n";
    let batch = lift(src);
    let (is_pub_e, _, _) = vis_props(&batch, NodeKind::Method, "Epsilon");
    assert!(is_pub_e);
    let (is_pub_z, _, _) = vis_props(&batch, NodeKind::Method, "zeta");
    assert!(!is_pub_z);
}

#[test]
fn go_capital_interface_is_exported() {
    let batch = lift("package p\ntype Eta interface { F() }\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Eta");
    assert!(is_pub);
    assert_eq!(label, "exported");
}
