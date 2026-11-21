//! Integration tests: every Function / Method / Class node the Rust
//! frontend lifts must carry `is_pub` / `is_export` / `visibility` props.
//!
//! Drives the public [`RustFrontend`] surface to assert end-to-end that
//! visibility detection survives parse → lift → batch.

use cc_cpg::{CpgWriteBatch, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_rust::RustFrontend;

/// Lift `source`, return the populated batch.
fn lift(source: &str) -> CpgWriteBatch {
    let frontend = RustFrontend::new();
    let tree = frontend.parse(source).expect("parse");
    let mut batch = CpgWriteBatch::new();
    frontend
        .lift(&tree, source, &mut batch, FileId::new(1))
        .expect("lift");
    batch
}

/// Find the first node whose `name` prop equals `name` and kind equals
/// `kind`; return the bool / string visibility props for assertion.
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
fn rust_pub_function_is_public() {
    let batch = lift("pub fn alpha() {}");
    let (is_pub, is_export, label) = vis_props(&batch, NodeKind::Function, "alpha");
    assert!(is_pub, "pub fn must be public");
    assert!(!is_export, "rust never sets is_export");
    assert_eq!(label, "public");
}

#[test]
fn rust_private_function_defaults_private() {
    let batch = lift("fn beta() {}");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "beta");
    assert!(!is_pub);
    assert_eq!(label, "private");
}

#[test]
fn rust_pub_crate_is_crate() {
    let batch = lift("pub(crate) fn gamma() {}");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "gamma");
    assert!(is_pub);
    assert_eq!(label, "crate");
}

#[test]
fn rust_pub_super_is_super() {
    let batch = lift("pub(super) fn delta() {}");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "delta");
    assert!(is_pub);
    assert_eq!(label, "super");
}

#[test]
fn rust_pub_in_path_is_restricted() {
    let batch = lift("pub(in crate::foo) fn epsilon() {}");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "epsilon");
    assert!(is_pub);
    assert_eq!(label, "restricted");
}

#[test]
fn rust_pub_struct_is_public() {
    let batch = lift("pub struct Zeta;");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Zeta");
    assert!(is_pub);
    assert_eq!(label, "public");
}

#[test]
fn rust_private_struct_defaults_private() {
    let batch = lift("struct Eta;");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Eta");
    assert!(!is_pub);
    assert_eq!(label, "private");
}

#[test]
fn rust_pub_enum_is_public() {
    let batch = lift("pub enum Theta { A, B }");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Theta");
    assert!(is_pub);
    assert_eq!(label, "public");
}

#[test]
fn rust_pub_trait_is_public() {
    let batch = lift("pub trait Iota { fn k(&self); }");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Iota");
    assert!(is_pub);
    assert_eq!(label, "public");
}

#[test]
fn rust_method_inherits_visibility_modifier() {
    let src = "struct S; impl S { pub fn kappa(&self) {} fn lambda(&self) {} }";
    let batch = lift(src);
    let (is_pub_k, _, label_k) = vis_props(&batch, NodeKind::Method, "kappa");
    assert!(is_pub_k, "pub method visible");
    assert_eq!(label_k, "public");
    let (is_pub_l, _, label_l) = vis_props(&batch, NodeKind::Method, "lambda");
    assert!(!is_pub_l);
    assert_eq!(label_l, "private");
}
