//! Lifters for `import_statement`, `import_clause`, decorators, and
//! comments.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;

/// Try to handle `node` as an import / decorator / comment.
pub(crate) fn dispatch(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    parent: NodeId,
) -> Option<NodeId> {
    match node.kind() {
        "import_statement" => Some(lift_import(ctx, store, node)),
        "decorator" => Some(lift_decorator(ctx, store, node, parent)),
        "comment" => Some(lift_comment(ctx, store, node)),
        _ => None,
    }
}

/// Lift an `import_statement`. We capture three pieces: the originating
/// module path (the `source` field), the list of imported names, and an
/// `import_kind` tag (`default` / `named` / `namespace` / `bare`).
fn lift_import(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let module_path = node
        .child_by_field_name("source")
        .map_or(String::new(), |n| {
            strip_string_quotes(node_text(n, ctx.bytes())).to_owned()
        });
    let (kind_label, names) = classify_import(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Import)
        .with_prop("import_kind", intern_string(store, kind_label))
        .with_prop("module_path", intern_string(store, &module_path))
        .with_prop("names_imported", Value::String(names.join(",")))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Classify the import shape and collect every imported binding name.
///
/// Handles the five common forms:
///
/// - `import "foo";`              -> `bare`
/// - `import foo from "bar";`     -> `default`
/// - `import { a, b } from "x";`  -> `named`
/// - `import * as ns from "x";`   -> `namespace`
/// - mixed `import foo, { a }`    -> `named` (with both names captured)
fn classify_import(node: TsNode<'_>, bytes: &[u8]) -> (&'static str, Vec<String>) {
    let Some(clause) = find_named_child(node, "import_clause") else {
        return ("bare", Vec::new());
    };
    let mut names: Vec<String> = Vec::new();
    let mut kind: &'static str = "default";
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                names.push(node_text(child, bytes).to_owned());
            }
            "named_imports" => {
                kind = "named";
                collect_named_imports(child, bytes, &mut names);
            }
            "namespace_import" => {
                kind = "namespace";
                if let Some(alias) = child.named_child(0) {
                    names.push(node_text(alias, bytes).to_owned());
                }
            }
            _ => {}
        }
    }
    (kind, names)
}

/// Collect the renamed bindings inside a `named_imports` block.
fn collect_named_imports(node: TsNode<'_>, bytes: &[u8], out: &mut Vec<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "import_specifier" {
            let alias = child
                .child_by_field_name("alias")
                .or_else(|| child.child_by_field_name("name"));
            if let Some(n) = alias {
                out.push(node_text(n, bytes).to_owned());
            }
        }
    }
}

/// Find the first named child with `kind`, walking only direct children.
fn find_named_child<'tree>(node: TsNode<'tree>, kind: &str) -> Option<TsNode<'tree>> {
    let mut cursor = node.walk();
    let result = node.named_children(&mut cursor).find(|c| c.kind() == kind);
    result
}

/// Strip surrounding `'` or `"` from a string-literal node text.
fn strip_string_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '\'' || c == '"' || c == '`')
}

/// Lift a `decorator` line into a [`NodeKind::Decorator`] node.
fn lift_decorator(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
    _parent: NodeId,
) -> NodeId {
    let raw = node_text(node, ctx.bytes());
    let body = raw.trim().trim_start_matches('@').trim();
    let builder = NodeBuilder::new(NodeKind::Decorator)
        .with_prop("expression", intern_string(store, body))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift a `comment` token into a [`NodeKind::Comment`] node, classifying
/// `//` (line), `/* */` (block), and `/** */` (jsdoc).
fn lift_comment(ctx: &LiftCtx<'_>, store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let text = node_text(node, ctx.bytes());
    let comment_kind = classify_comment(text);
    let builder = NodeBuilder::new(NodeKind::Comment)
        .with_prop("text", intern_string(store, text))
        .with_prop("kind", intern_string(store, comment_kind))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Classify the comment text. `JSDoc` (`/** ... */`) is a TypeScript-aware
/// special case because the type-aware lint surface frequently keys off it.
fn classify_comment(text: &str) -> &'static str {
    if text.starts_with("/**") {
        "jsdoc"
    } else if text.starts_with("/*") {
        "block"
    } else {
        "line"
    }
}
