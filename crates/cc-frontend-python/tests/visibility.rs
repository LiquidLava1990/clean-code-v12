//! Integration tests: every Function / Method / Class node the Python
//! frontend lifts must carry `is_pub` / `is_export` / `visibility` props.

use cc_cpg::{CpgWriteBatch, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_python::PythonFrontend;

fn lift(source: &str) -> CpgWriteBatch {
    let frontend = PythonFrontend::new();
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
fn python_normal_function_is_public() {
    let batch = lift("def alpha():\n    pass\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "alpha");
    assert!(is_pub);
    assert_eq!(label, "public");
}

#[test]
fn python_underscore_function_is_private() {
    let batch = lift("def _beta():\n    pass\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "_beta");
    assert!(!is_pub);
    assert_eq!(label, "private");
}

#[test]
fn python_double_underscore_function_is_name_mangled() {
    let batch = lift("def __gamma():\n    pass\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Function, "__gamma");
    assert!(!is_pub);
    assert_eq!(label, "name_mangled");
}

#[test]
fn python_dunder_function_is_public() {
    let src = "class C:\n    def __init__(self):\n        pass\n";
    let batch = lift(src);
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Method, "__init__");
    assert!(is_pub, "dunder methods are public-API");
    assert_eq!(label, "public");
}

#[test]
fn python_class_is_public() {
    let batch = lift("class Delta:\n    pass\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "Delta");
    assert!(is_pub);
    assert_eq!(label, "public");
}

#[test]
fn python_underscore_class_is_private() {
    let batch = lift("class _Epsilon:\n    pass\n");
    let (is_pub, _, label) = vis_props(&batch, NodeKind::Class, "_Epsilon");
    assert!(!is_pub);
    assert_eq!(label, "private");
}
