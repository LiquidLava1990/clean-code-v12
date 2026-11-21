//! Integration tests: every Function / Method / Class node the TS
//! frontend lifts must carry `is_pub` / `is_export` / `visibility` props.

use cc_cpg::{CpgWriteBatch, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_typescript::TypescriptFrontend;

fn lift(source: &str) -> CpgWriteBatch {
    let frontend = TypescriptFrontend::new();
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
fn ts_exported_function_is_public() {
    let batch = lift("export function alpha() {}\n");
    let (is_pub, is_export, label) = vis_props(&batch, NodeKind::Function, "alpha");
    assert!(is_pub);
    assert!(is_export);
    assert_eq!(label, "public");
}

#[test]
fn ts_unexported_function_is_private() {
    let batch = lift("function beta() {}\n");
    let (is_pub, is_export, label) = vis_props(&batch, NodeKind::Function, "beta");
    assert!(!is_pub);
    assert!(!is_export);
    assert_eq!(label, "private");
}

#[test]
fn ts_exported_class_is_public() {
    let batch = lift("export class Gamma {}\n");
    let (is_pub, is_export, label) = vis_props(&batch, NodeKind::Class, "Gamma");
    assert!(is_pub);
    assert!(is_export);
    assert_eq!(label, "public");
}

#[test]
fn ts_unexported_class_is_private() {
    let batch = lift("class Delta {}\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Delta");
    assert!(!is_pub);
    assert_eq!(label, "private");
}

#[test]
fn ts_class_member_private_overrides_export() {
    let src = "export class Eps { private hush() {} public shout() {} }\n";
    let batch = lift(src);
    let (is_pub_h, _, label_h) = vis_props(&batch, NodeKind::Method, "hush");
    assert!(!is_pub_h);
    assert_eq!(label_h, "private");
    let (is_pub_s, _, label_s) = vis_props(&batch, NodeKind::Method, "shout");
    assert!(is_pub_s);
    assert_eq!(label_s, "public");
}

#[test]
fn ts_export_default_function_is_public() {
    let batch = lift("export default function zeta() {}\n");
    let (is_pub, is_export, label) = vis_props(&batch, NodeKind::Function, "zeta");
    assert!(is_pub);
    assert!(is_export);
    assert_eq!(label, "public");
}
