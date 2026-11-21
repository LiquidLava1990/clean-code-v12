//! Lifters for `import_statement`, `import_from_statement`, decorators,
//! and comments.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;

/// Lift `import` / `from … import …` / `__future__` imports.
///
/// We capture three pieces: the originating module path, the list of
/// imported names, and an `import_kind` tag (`absolute` / `from` /
/// `future`). Aliases (`as foo`) are folded into the imported names.
pub(crate) fn lift_import(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let kind_label = match node.kind() {
        "import_statement" => "absolute",
        "import_from_statement" => "from",
        "future_import_statement" => "future",
        other => other,
    };
    let module_path = extract_module_path(node, ctx.bytes());
    let names = extract_imported_names(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Import)
        .with_prop("import_kind", intern_string(store, kind_label))
        .with_prop("module_path", intern_string(store, &module_path))
        .with_prop("names_imported", Value::String(names.join(",")))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Pull the source module string from an import node — the
/// `module_name` field for `import_from_statement`, or the first
/// `dotted_name` child for plain `import_statement`.
fn extract_module_path(node: TsNode<'_>, bytes: &[u8]) -> String {
    if let Some(m) = node.child_by_field_name("module_name") {
        return node_text(m, bytes).to_owned();
    }
    let mut cursor = node.walk();
    for c in node.named_children(&mut cursor) {
        if matches!(c.kind(), "dotted_name" | "relative_import") {
            return node_text(c, bytes).to_owned();
        }
    }
    String::new()
}

/// Collect every imported binding name from an import node.
///
/// Handles bare `import foo`, `import foo as bar`, `from x import a, b`,
/// and `from x import a as b, c`.
fn extract_imported_names(node: TsNode<'_>, bytes: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    let mut out: Vec<String> = Vec::new();
    let saw_module = node.kind() == "import_from_statement";
    let mut skipped_module = !saw_module;
    for child in node.named_children(&mut cursor) {
        if !skipped_module {
            // First named child is the module path for `from … import …`.
            skipped_module = true;
            continue;
        }
        match child.kind() {
            "aliased_import" | "import_alias" => {
                let aliased = child
                    .child_by_field_name("alias")
                    .or_else(|| child.child_by_field_name("name"))
                    .map_or_else(
                        || node_text(child, bytes).to_owned(),
                        |n| node_text(n, bytes).to_owned(),
                    );
                out.push(aliased);
            }
            "dotted_name" | "identifier" => {
                out.push(node_text(child, bytes).to_owned());
            }
            "wildcard_import" => out.push("*".to_owned()),
            _ => {}
        }
    }
    out
}

/// Lift a `decorator` line into a [`NodeKind::Decorator`] node.
pub(crate) fn lift_decorator(
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

/// Lift a `comment` token into a [`NodeKind::Comment`] node, with
/// best-effort classification: `coding` magic, docstring, or plain `line`.
pub(crate) fn lift_comment(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let text = node_text(node, ctx.bytes());
    let comment_kind = classify_comment(text);
    let builder = NodeBuilder::new(NodeKind::Comment)
        .with_prop("text", intern_string(store, text))
        .with_prop("kind", intern_string(store, comment_kind))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Classify the comment text. `# coding: ...` is a magic encoding line
/// per PEP 263; triple-quoted block strings used as docstrings would have
/// already been lifted as `string` literals, so we only see token-style
/// `#` comments here.
fn classify_comment(text: &str) -> &'static str {
    let trimmed = text.trim_start_matches('#').trim();
    if trimmed.starts_with("coding:") || trimmed.starts_with("coding=") {
        "coding"
    } else if text.starts_with("\"\"\"") || text.starts_with("'''") {
        "docstring"
    } else if text.contains('\n') {
        "block"
    } else {
        "line"
    }
}
