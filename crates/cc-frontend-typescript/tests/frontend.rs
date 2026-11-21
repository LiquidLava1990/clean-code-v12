//! Integration tests covering the full parse + lift pipeline for the
//! TypeScript / TSX / JavaScript frontend.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_typescript::TypescriptFrontend;

/// Helper: parse + lift a TS source string, returning the populated batch
/// + the file node id.
fn lift_ts(src: &str) -> (CpgWriteBatch, cc_cpg::NodeId) {
    let frontend = TypescriptFrontend::new();
    let tree = frontend.parse(src).expect("parse");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, src, &mut batch, FileId::new(1))
        .expect("lift");
    (batch, file_id)
}

/// Helper: parse + lift a TSX source string.
fn lift_tsx(src: &str) -> (CpgWriteBatch, cc_cpg::NodeId) {
    let frontend = TypescriptFrontend::new();
    let tree = frontend.parse_tsx(src).expect("parse tsx");
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

/// Borrow a `bool`-typed property.
fn bool_prop(node: &cc_cpg::Node, key: &str) -> Option<bool> {
    node.prop(key).and_then(Value::as_bool)
}

/// Pull a string field from the `lang_ext` map.
fn lang_ext_str<'a>(node: &'a cc_cpg::Node, key: &str) -> Option<&'a str> {
    let Some(Value::Map(map)) = node.prop("lang_ext") else {
        return None;
    };
    map.get(key).and_then(Value::as_str)
}

/// Pull a bool field from the `lang_ext` map.
fn lang_ext_bool(node: &cc_cpg::Node, key: &str) -> Option<bool> {
    let Some(Value::Map(map)) = node.prop("lang_ext") else {
        return None;
    };
    map.get(key).and_then(Value::as_bool)
}

#[test]
fn parses_empty_file() {
    let (batch, file_id) = lift_ts("");
    assert_eq!(file_id.get(), 1);
    assert_eq!(count_kind(&batch, NodeKind::File), 1);
    assert_eq!(count_kind(&batch, NodeKind::Module), 1);
}

#[test]
fn parses_hello_world() {
    let src = std::fs::read_to_string("tests/fixtures/hello.ts").expect("fixture");
    let (batch, _) = lift_ts(&src);
    let funcs: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .collect();
    assert_eq!(funcs.len(), 1, "expected exactly one Function");
    let f = funcs[0];
    assert_eq!(string_prop(f, "name"), Some("main"));
    assert!(matches!(f.prop("line_start"), Some(Value::Uint(1))));
}

#[test]
fn parses_class_with_methods() {
    let src = std::fs::read_to_string("tests/fixtures/classes.ts").expect("fixture");
    let (batch, _) = lift_ts(&src);
    assert_eq!(count_kind(&batch, NodeKind::Class), 1);
    let methods = count_kind(&batch, NodeKind::Method);
    assert!(
        methods >= 3,
        "expected at least 3 methods (ctor + 2), got {methods}"
    );
    for n in batch.nodes().iter().filter(|n| n.kind == NodeKind::Method) {
        assert_eq!(
            lang_ext_bool(n, "is_method"),
            Some(true),
            "method missing lang_ext.is_method = true"
        );
    }
}

#[test]
fn parses_arrow_function() {
    let src = "const f = (x: number) => x + 1;\n";
    let (batch, _) = lift_ts(src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function)
        .expect("arrow Function");
    assert_eq!(
        lang_ext_bool(f, "is_arrow"),
        Some(true),
        "arrow lang_ext.is_arrow != true"
    );
}

#[test]
fn parses_async_function() {
    let src = "async function f(): Promise<void> {}\n";
    let (batch, _) = lift_ts(src);
    let f = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function)
        .expect("function");
    assert_eq!(bool_prop(f, "is_async"), Some(true));
    assert_eq!(lang_ext_str(f, "async_kind"), Some("coroutine"));
}

#[test]
fn parses_decorator() {
    let src = std::fs::read_to_string("tests/fixtures/decorators.ts").expect("fixture");
    let (batch, _) = lift_ts(&src);
    let class = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Class)
        .expect("class");
    let decorators = string_prop(class, "decorators").unwrap_or("");
    assert!(
        decorators.contains("logged"),
        "decorators prop did not contain `logged`: {decorators:?}"
    );
}

#[test]
fn parses_try_catch_with_types() {
    let src = std::fs::read_to_string("tests/fixtures/try_catch.ts").expect("fixture");
    let (batch, _) = lift_ts(&src);
    // One outer Try + at least one catch_clause Try entry.
    let try_count = count_kind(&batch, NodeKind::Try);
    assert!(
        try_count >= 2,
        "expected >=2 Try nodes (outer + catch), got {try_count}"
    );
    let catch = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Try)
        .find(|n| string_prop(n, "exception_type").is_some_and(|t| !t.is_empty()))
        .expect("a Try node carrying an exception_type");
    let exc = string_prop(catch, "exception_type").unwrap_or("");
    assert!(
        exc.contains("unknown") || exc.contains('e'),
        "exception_type: {exc:?}"
    );
}

#[test]
fn parses_nested_class_function() {
    let src = "class A {\n    m() { function inner() {} }\n}\n";
    let (batch, _) = lift_ts(src);
    // The class has one method (m) plus the nested `inner` is a
    // declaration-shaped Function inside the method body. Either way the
    // Method <- Class AST_PARENT edge must be present.
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
    let has_edge = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::AST_PARENT && e.from == method.id && e.to == class.id);
    assert!(has_edge, "no AST_PARENT edge from method to class");
}

#[test]
fn parses_import_named() {
    let src = "import { foo, bar as baz } from \"mod\";\n";
    let (batch, _) = lift_ts(src);
    let imp = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Import)
        .expect("import");
    assert_eq!(string_prop(imp, "import_kind"), Some("named"));
    let names = string_prop(imp, "names_imported").unwrap_or("");
    assert!(
        names.contains("foo") && names.contains("baz"),
        "names: {names:?}"
    );
    assert_eq!(string_prop(imp, "module_path"), Some("mod"));
}

#[test]
fn parses_string_kinds() {
    let cases = [
        ("const a = \"hi\";\n", "str"),
        ("const a = `hi ${1}`;\n", "template"),
        ("const a = /foo/g;\n", "regex"),
        ("const a = 42;\n", "num"),
    ];
    for (src, want) in cases {
        let (batch, _) = lift_ts(src);
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
    let src = std::fs::read_to_string("tests/fixtures/syntax_error.ts").expect("fixture");
    let frontend = TypescriptFrontend::new();
    let tree = frontend.parse(&src).expect("partial parse must succeed");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, &src, &mut batch, FileId::new(1))
        .expect("lift partial");
    assert_eq!(file_id.get(), 1);
    // At least the File + Module nodes plus *something* lifted.
    assert!(batch.nodes().len() >= 2);
}

#[test]
fn parameter_position_indexed() {
    let src = "function f(a: number, b: number, c: number) {}\n";
    let (batch, _) = lift_ts(src);
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
fn parses_jsx_component() {
    let src = std::fs::read_to_string("tests/fixtures/jsx.tsx").expect("fixture");
    let (batch, _) = lift_tsx(&src);
    let hello = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .find(|n| string_prop(n, "name") == Some("HelloPanel"))
        .expect("HelloPanel function");
    assert_eq!(
        lang_ext_bool(hello, "is_react_component"),
        Some(true),
        "PascalCase function returning JSX should be classified as React component"
    );
}

#[test]
fn parses_generic_function() {
    let src = std::fs::read_to_string("tests/fixtures/generics.ts").expect("fixture");
    let (batch, _) = lift_ts(&src);
    let pair = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .find(|n| string_prop(n, "name") == Some("pair"))
        .expect("pair function");
    let generics = lang_ext_str(pair, "generics").unwrap_or("");
    assert!(
        generics.contains('A') && generics.contains('B'),
        "generics list: {generics:?}"
    );
}

#[test]
fn declares_edge_from_module_to_top_level_class() {
    let (batch, _) = lift_ts("class C {}\n");
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
    assert!(has_declares, "missing DECLARES edge module -> class");
}
