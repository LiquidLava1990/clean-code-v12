//! Integration tests for the Go frontend — full parse + lift pipeline.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeKind, Value};
use cc_frontend::{FileId, LanguageFrontend};
use cc_frontend_go::GoFrontend;

/// Helper: parse + lift, returning the populated batch + the file node id.
fn lift(src: &str) -> (CpgWriteBatch, cc_cpg::NodeId) {
    let frontend = GoFrontend::new();
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

/// Read a flag from a function's `lang_ext` `Value::Map`.
fn lang_ext_bool(node: &cc_cpg::Node, key: &str) -> Option<bool> {
    let Some(Value::Map(map)) = node.prop("lang_ext") else {
        return None;
    };
    match map.get(key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
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
    let src = std::fs::read_to_string("tests/fixtures/hello.go").expect("read fixture");
    let (batch, _) = lift(&src);
    let funcs: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Function)
        .collect();
    assert_eq!(funcs.len(), 1, "expected one Function, got {}", funcs.len());
    assert_eq!(string_prop(funcs[0], "name"), Some("main"));
    // package main → Module.name should be "main".
    let module = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Module)
        .expect("module");
    assert_eq!(string_prop(module, "name"), Some("main"));
}

#[test]
fn parses_method_with_receiver() {
    let src = std::fs::read_to_string("tests/fixtures/struct_methods.go").expect("fixture");
    let (batch, _) = lift(&src);
    let methods: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Method)
        .collect();
    assert!(
        methods.len() >= 2,
        "expected ≥2 methods, got {}",
        methods.len()
    );
    // At least one method has a pointer receiver "*Rect".
    let has_ptr_receiver = methods.iter().any(|m| {
        let Some(Value::Map(ext)) = m.prop("lang_ext") else {
            return false;
        };
        matches!(ext.get("receiver_type"), Some(Value::String(s)) if s.contains("Rect"))
    });
    assert!(
        has_ptr_receiver,
        "no method had a Rect-bearing receiver_type"
    );
}

#[test]
fn parses_struct_with_methods() {
    let src = std::fs::read_to_string("tests/fixtures/struct_methods.go").expect("fixture");
    let (batch, _) = lift(&src);
    assert!(count_kind(&batch, NodeKind::Class) >= 1, "no struct lifted");
    // The free function NewRect should be a Function (not a Method).
    let new_rect = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("NewRect"))
        .expect("NewRect function");
    let recv = match new_rect.prop("lang_ext") {
        Some(Value::Map(m)) => m.get("receiver_type"),
        _ => None,
    };
    assert_eq!(
        recv,
        Some(&Value::Null),
        "free fn should have receiver_type=Null"
    );
}

#[test]
fn parses_interface_methods() {
    let src = std::fs::read_to_string("tests/fixtures/interface.go").expect("fixture");
    let (batch, _) = lift(&src);
    let interfaces: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Class && string_prop(n, "kind") == Some("interface"))
        .collect();
    assert!(
        interfaces.len() >= 2,
        "expected ≥2 interface classes, got {}",
        interfaces.len()
    );
}

#[test]
fn parses_goroutine() {
    let src = std::fs::read_to_string("tests/fixtures/goroutines.go").expect("fixture");
    let (batch, _) = lift(&src);
    let spawner = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("spawner"))
        .expect("spawner function");
    assert_eq!(
        lang_ext_bool(spawner, "goroutine_spawned"),
        Some(true),
        "spawner should have goroutine_spawned=true"
    );
    let plain = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("plain"))
        .expect("plain function");
    assert_eq!(
        lang_ext_bool(plain, "goroutine_spawned"),
        Some(false),
        "plain should have goroutine_spawned=false"
    );
    // At least one Async wrapper from the `go` statements.
    assert!(count_kind(&batch, NodeKind::Async) >= 1);
}

#[test]
fn parses_for_range() {
    let src = std::fs::read_to_string("tests/fixtures/for_range.go").expect("fixture");
    let (batch, _) = lift(&src);
    // 3 functions × ≥1 loop each.
    assert!(
        count_kind(&batch, NodeKind::Loop) >= 3,
        "expected ≥3 loops, got {}",
        count_kind(&batch, NodeKind::Loop)
    );
}

#[test]
fn parses_type_switch() {
    let src = std::fs::read_to_string("tests/fixtures/type_switch.go").expect("fixture");
    let (batch, _) = lift(&src);
    // A type_switch + a select are both Branches.
    assert!(
        count_kind(&batch, NodeKind::Branch) >= 2,
        "expected ≥2 branches, got {}",
        count_kind(&batch, NodeKind::Branch)
    );
}

#[test]
fn parses_select() {
    let src = "package p\nfunc f(ch chan int) { select { case x := <-ch: _ = x; default: } }\n";
    let (batch, _) = lift(src);
    assert!(
        count_kind(&batch, NodeKind::Branch) >= 1,
        "select should produce ≥1 Branch"
    );
}

#[test]
fn parses_defer() {
    let src = std::fs::read_to_string("tests/fixtures/defer.go").expect("fixture");
    let (batch, _) = lift(&src);
    assert!(
        count_kind(&batch, NodeKind::Try) >= 1,
        "defer should produce a Try wrapper"
    );
}

#[test]
fn parses_import_block() {
    let src =
        "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t. \"strings\"\n\t_ \"image/png\"\n)\n";
    let (batch, _) = lift(src);
    let imports: Vec<&cc_cpg::Node> = batch
        .nodes()
        .iter()
        .filter(|n| n.kind == NodeKind::Import)
        .collect();
    assert_eq!(
        imports.len(),
        4,
        "expected 4 imports, got {}",
        imports.len()
    );
    let kinds: Vec<&str> = imports
        .iter()
        .filter_map(|n| string_prop(n, "import_kind"))
        .collect();
    assert!(kinds.contains(&"absolute"));
    assert!(kinds.contains(&"dot"));
    assert!(kinds.contains(&"blank"));
}

#[test]
fn parses_with_syntax_error_partial() {
    let src = std::fs::read_to_string("tests/fixtures/syntax_error.go").expect("fixture");
    let frontend = GoFrontend::new();
    let tree = frontend.parse(&src).expect("partial parse");
    let mut batch = CpgWriteBatch::new();
    let file_id = frontend
        .lift(&tree, &src, &mut batch, FileId::new(1))
        .expect("lift partial");
    assert_eq!(file_id.get(), 1);
    // The good function should still surface.
    let ok = batch
        .nodes()
        .iter()
        .any(|n| n.kind == NodeKind::Function && string_prop(n, "name") == Some("ok"));
    assert!(ok, "the well-formed function `ok` should still be lifted");
}

#[test]
fn parameter_position_indexed() {
    let src = "package p\nfunc f(a int, b string, c bool) {}\n";
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
    assert_eq!(params.len(), 3, "expected 3 params, got {}", params.len());
    for (i, p) in params.iter().enumerate() {
        assert_eq!(p.prop("position"), Some(&Value::Uint(i as u64)));
    }
}

#[test]
fn declares_edge_from_module_to_top_level_function() {
    let (batch, _) = lift("package p\nfunc f() {}\n");
    let module = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Module)
        .expect("module");
    let func = batch
        .nodes()
        .iter()
        .find(|n| n.kind == NodeKind::Function)
        .expect("function");
    let has_declares = batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::DECLARES && e.from == module.id && e.to == func.id);
    assert!(has_declares, "missing DECLARES edge module → function");
}
