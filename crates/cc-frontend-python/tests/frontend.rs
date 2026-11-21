//! Integration tests covering the full parse + lift pipeline.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_python::PythonFrontend;

/// Helper: parse + lift, returning the populated batch + the file node id.
fn lift(src: &str) -> (CpgWriteBatch, cc_cpg::NodeId) {
    let frontend = PythonFrontend::new();
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

#[test]
fn parses_empty_file() {
    let (batch, file_id) = lift("");
    assert_eq!(file_id.get(), 1);
    // Empty source still gives File + Module — no other lifted nodes.
    assert_eq!(count_kind(&batch, NodeKind::File), 1);
    assert_eq!(count_kind(&batch, NodeKind::Module), 1);
}

#[test]
fn parses_hello_world() {
    let (batch, _) = lift("def main():\n    print(\"hello\")\n");
    let funcs: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .collect();
    assert_eq!(funcs.len(), 1);
    let f = funcs[0];
    assert_eq!(string_prop(f, "name"), Some("main"));
    assert_eq!(f.prop("line_start").and_then(Value::as_int), None);
    // line_start is `Uint(1)`.
    assert!(matches!(f.prop("line_start"), Some(Value::Uint(1))));
}

#[test]
fn parses_class_with_methods() {
    let src = std::fs::read_to_string("tests/fixtures/classes.py").expect("read fixture");
    let (batch, _) = lift(&src);
    assert_eq!(count_kind(&batch, NodeKind::Class), 1);
    let methods = count_kind(&batch, NodeKind::Method);
    assert!(methods >= 3, "expected at least 3 methods, got {methods}");
    // All Methods carry lang_ext.is_method = true.
    for n in batch.nodes().iter().filter(|n| n.kind == NodeKind::Method) {
        if let Some(Value::Map(ext)) = n.prop("lang_ext") {
            assert_eq!(ext.get("is_method"), Some(&Value::Bool(true)));
        } else {
            panic!("method missing lang_ext");
        }
    }
}

#[test]
fn parses_async_def_marks_async() {
    let (batch, _) = lift("async def f(): pass\n");
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function)
        .expect("function");
    assert_eq!(f.prop("is_async"), Some(&Value::Bool(true)));
    if let Some(Value::Map(ext)) = f.prop("lang_ext") {
        assert_eq!(
            ext.get("async_kind").and_then(Value::as_str),
            Some("coroutine")
        );
    } else {
        panic!("missing lang_ext");
    }
}

#[test]
fn parses_decorator_chain() {
    let src = "@a\n@b\ndef f(): pass\n";
    let (batch, _) = lift(src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function)
        .expect("function");
    let decorators = string_prop(f, "decorators").unwrap_or("");
    assert!(
        decorators.contains('a') && decorators.contains('b'),
        "decorators prop: {decorators:?}"
    );
}

#[test]
fn parses_try_except_with_types() {
    let src = std::fs::read_to_string("tests/fixtures/try_except.py").expect("fixture");
    let (batch, _) = lift(&src);
    // One outer Try + at least two except-clause Try entries (3 total).
    let try_count = count_kind(&batch, NodeKind::Try);
    assert!(
        try_count >= 3,
        "expected at least 3 Try nodes, got {try_count}"
    );
}

#[test]
fn parses_nested_function_in_class() {
    let src = "class A:\n    def m(self):\n        pass\n";
    let (batch, _) = lift(src);
    let class = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Class)
        .expect("class");
    let method = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Method)
        .expect("method");
    // Verify AST_PARENT chain method → class.
    let has_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::AST_PARENT && e.from == method.id && e.to == class.id);
    assert!(has_edge, "no AST_PARENT edge from method to class");
}

#[test]
fn parses_import_from() {
    let src = "from os import path, sep\n";
    let (batch, _) = lift(src);
    let imp = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Import)
        .expect("import");
    assert_eq!(string_prop(imp, "import_kind"), Some("from"));
    let names = string_prop(imp, "names_imported").unwrap_or("");
    assert!(
        names.contains("path") && names.contains("sep"),
        "names: {names:?}"
    );
}

#[test]
fn parses_string_literal_kinds() {
    let cases = [
        ("\"hi\"\n", "str"),
        ("b\"hi\"\n", "bytes"),
        ("r\"hi\"\n", "raw"),
        ("f\"{x}\"\n", "fstring"),
    ];
    for (src, want) in cases {
        let (batch, _) = lift(src);
        let lit = batch
            .nodes()
            .iter()
            .find(|n| n.kind == NodeKind::Literal)
            .unwrap_or_else(|| panic!("no literal in {src:?}"));
        let got = string_prop(lit, "literal_kind").unwrap_or("?");
        assert_eq!(got, want, "src {src:?}");
    }
}

#[test]
fn parses_with_syntax_error_partial() {
    let src = "def f(:\n    pass\n";
    let frontend = PythonFrontend::new();
    let tree = frontend
        .parse(src)
        .expect("partial parse must still succeed");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, src, &mut batch, FileId::new(1))
        .expect("lift partial");
    assert_eq!(file_id.get(), 1);
}

#[test]
fn parameter_position_indexed() {
    let src = "def f(a, b, c): pass\n";
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
fn lifts_match_statement() {
    let src = std::fs::read_to_string("tests/fixtures/match_stmt.py").expect("fixture");
    let (batch, _) = lift(&src);
    // At least one Branch (the match itself).
    assert!(count_kind(&batch, NodeKind::Branch) >= 1);
}

#[test]
fn roundtrip_lifts_self_source() {
    // Lift the hello-world fixture as a stand-in for "non-trivial Python".
    let src = std::fs::read_to_string("tests/fixtures/hello.py").expect("fixture");
    let (batch, _) = lift(&src);
    assert!(
        batch.nodes().len() > 5,
        "expected >5 nodes from hello.py lift, got {}",
        batch.nodes().len()
    );
}

#[test]
fn declares_edge_from_module_to_top_level_class() {
    let (batch, _) = lift("class C: pass\n");
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
    assert!(has_declares, "missing DECLARES edge module → class");
}
