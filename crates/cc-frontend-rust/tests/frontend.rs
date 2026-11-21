//! Integration tests covering the full parse + lift pipeline.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_rust::RustFrontend;

/// Helper: parse + lift, returning the populated batch + the file node id.
fn lift(src: &str) -> (CpgWriteBatch, cc_cpg::NodeId) {
    let frontend = RustFrontend::new();
    let tree = frontend.parse(src).expect("parse");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, src, &mut batch, FileId::new(1))
        .expect("lift");
    (batch, file_id)
}

/// Count nodes of a given kind.
fn count_kind(batch: &CpgWriteBatch, kind: NodeKind) -> usize {
    batch.nodes().iter().filter(|n| n.kind == kind).count()
}

/// Borrow a `String`-typed property.
fn string_prop<'a>(node: &'a cc_cpg::Node, key: &str) -> Option<&'a str> {
    node.prop(key).and_then(Value::as_str)
}

/// Read a `bool` from a function's `lang_ext` map.
fn lang_ext_bool(node: &cc_cpg::Node, key: &str) -> Option<bool> {
    if let Some(Value::Map(m)) = node.prop("lang_ext") {
        if let Some(Value::Bool(b)) = m.get(key) {
            return Some(*b);
        }
    }
    None
}

/// Read a `String` from a function's `lang_ext` map.
fn lang_ext_string<'a>(node: &'a cc_cpg::Node, key: &str) -> Option<&'a str> {
    if let Some(Value::Map(m)) = node.prop("lang_ext") {
        if let Some(Value::String(s)) = m.get(key) {
            return Some(s.as_str());
        }
    }
    None
}

#[test]
fn parses_empty_file() {
    let (batch, file_id) = lift("");
    assert_eq!(file_id.get(), 1);
    assert_eq!(count_kind(&batch, NodeKind::File), 1);
    assert_eq!(count_kind(&batch, NodeKind::Module), 1);
}

#[test]
fn parses_hello_world() {
    let src = std::fs::read_to_string("tests/fixtures/hello.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let funcs: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .collect();
    assert_eq!(funcs.len(), 1);
    let f = funcs[0];
    assert_eq!(string_prop(f, "name"), Some("main"));
    assert!(matches!(f.prop("line_start"), Some(Value::Uint(1))));
}

#[test]
fn parses_struct_with_impl_methods() {
    let src = std::fs::read_to_string("tests/fixtures/struct_impl.rs").expect("fixture");
    let (batch, _) = lift(&src);
    // Struct + at least 3 methods on the impl block.
    assert!(count_kind(&batch, NodeKind::Class) >= 1);
    let methods = count_kind(&batch, NodeKind::Method);
    assert!(methods >= 3, "expected ≥3 methods, got {methods}");
    // Methods must be tagged Method (not Function).
    let no_free_fn_named_new = !batch
        .nodes()
        .iter()
        .any(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("new"));
    assert!(
        no_free_fn_named_new,
        "method `new` was lifted as a free Function instead of Method"
    );
}

#[test]
fn parses_trait_definition() {
    let src = std::fs::read_to_string("tests/fixtures/traits.rs").expect("fixture");
    let (batch, _) = lift(&src);
    // Trait surfaces as a Class with kind="iface".
    let trait_node = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Class && string_prop(n, "kind") == Some("iface"))
        .expect("trait Class node");
    assert_eq!(string_prop(trait_node, "name"), Some("Speak"));
}

#[test]
fn parses_async_fn() {
    let src = std::fs::read_to_string("tests/fixtures/async_unsafe_const.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("fetch"))
        .expect("fetch fn");
    assert_eq!(f.prop("is_async"), Some(&Value::Bool(true)));
    assert_eq!(lang_ext_bool(f, "is_async"), Some(true));
}

#[test]
fn parses_unsafe_fn() {
    let src = std::fs::read_to_string("tests/fixtures/async_unsafe_const.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("dangerous"))
        .expect("dangerous fn");
    assert_eq!(lang_ext_bool(f, "is_unsafe"), Some(true));
}

#[test]
fn parses_const_fn() {
    let src = std::fs::read_to_string("tests/fixtures/async_unsafe_const.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("double"))
        .expect("double fn");
    assert_eq!(lang_ext_bool(f, "is_const_fn"), Some(true));
}

#[test]
fn parses_match_expression() {
    let src = std::fs::read_to_string("tests/fixtures/match_loop.rs").expect("fixture");
    let (batch, _) = lift(&src);
    assert!(
        count_kind(&batch, NodeKind::Branch) >= 1,
        "expected ≥1 Branch from match expression"
    );
}

#[test]
fn parses_loop_expression() {
    let src = std::fs::read_to_string("tests/fixtures/match_loop.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let loops = count_kind(&batch, NodeKind::Loop);
    assert!(
        loops >= 3,
        "expected ≥3 Loop nodes (for/while/loop), got {loops}"
    );
}

#[test]
fn parses_macro_invocation() {
    let src = std::fs::read_to_string("tests/fixtures/macros.rs").expect("fixture");
    let (batch, _) = lift(&src);
    // Every macro_invocation becomes a Call with is_dynamic=true.
    let dynamic_calls = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Call && n.prop("is_dynamic") == Some(&Value::Bool(true)))
        .count();
    assert!(
        dynamic_calls >= 3,
        "expected ≥3 dynamic macro calls, got {dynamic_calls}"
    );
}

#[test]
fn parses_attribute() {
    let src = std::fs::read_to_string("tests/fixtures/attributes.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let decorators = count_kind(&batch, NodeKind::Decorator);
    assert!(decorators >= 2, "expected ≥2 Decorators, got {decorators}");
}

#[test]
fn parses_use_declaration() {
    let src = "use std::io::{Read, Write as W};\n";
    let (batch, _) = lift(src);
    let imp = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Import)
        .expect("import");
    assert_eq!(string_prop(imp, "import_kind"), Some("use"));
    let names = string_prop(imp, "names_imported").unwrap_or("");
    assert!(
        names.contains("Read") && names.contains('W'),
        "names: {names:?}"
    );
}

#[test]
fn parses_lifetimes() {
    let src = std::fs::read_to_string("tests/fixtures/lifetimes.rs").expect("fixture");
    let (batch, _) = lift(&src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("longest"))
        .expect("longest fn");
    let lifetimes = lang_ext_string(f, "lifetimes").unwrap_or("");
    assert!(
        lifetimes.contains('\'') && lifetimes.contains('a') && lifetimes.contains('b'),
        "lifetimes: {lifetimes:?}"
    );
    let where_clauses = lang_ext_string(f, "where_clauses").unwrap_or("");
    assert!(
        where_clauses.contains("'b") && where_clauses.contains("'a"),
        "where_clauses: {where_clauses:?}"
    );
}

#[test]
fn parses_with_syntax_error_partial() {
    let src = std::fs::read_to_string("tests/fixtures/syntax_error.rs").expect("fixture");
    let frontend = RustFrontend::new();
    let tree = frontend.parse(&src).expect("partial parse must succeed");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, &src, &mut batch, FileId::new(1))
        .expect("lift partial");
    assert_eq!(file_id.get(), 1);
    // No panic, file produced; error markers permitted.
    assert!(!batch.nodes().is_empty());
}

#[test]
fn parameter_position_indexed() {
    let src = "fn f(a: i32, b: i32, c: i32) {}\n";
    let (batch, _) = lift(src);
    let mut params: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Parameter)
        .collect();
    params.sort_by_key(|n| match n.prop("position") {
        Some(Value::Uint(p)) => *p,
        _ => u64::MAX,
    });
    assert_eq!(params.len(), 3);
    for (i, p) in params.iter().enumerate() {
        assert_eq!(p.prop("position"), Some(&Value::Uint(i as u64)));
    }
}

#[test]
fn declares_edge_from_module_to_top_level_struct() {
    let (batch, _) = lift("pub struct S;\n");
    let module = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Module)
        .expect("module");
    let class = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Class)
        .expect("class");
    let has_declares = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::DECLARES && e.from == module.id && e.to == class.id);
    assert!(has_declares, "missing DECLARES edge module → struct");
}
