//! Lifters for `import_declaration` / `import_spec` and `comment` tokens.
//!
//! Go imports come in two flavours: a single inline `import "foo"` and a
//! parenthesised block `import ( … )` containing many `import_spec` rows.
//! Per the spec we emit one [`cc_cpg::NodeKind::Import`] per spec so the
//! `Module → DECLARES → Import` edge fan-out matches the source.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;

/// Lift an `import_declaration` (block form) or single `import_spec`.
///
/// For a block `import ( ... )`, we emit one Import node per inner
/// `import_spec` so each path is its own first-class node — the caller
/// receives the id of the *last* spec emitted (or a placeholder for an
/// empty block). The other Import nodes are still in the batch and reach
/// the parent via `AST_PARENT` edges via [`super::lift_children_into`].
pub(crate) fn lift_import(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    if node.kind() == "import_spec" {
        return build_import_node(store, node, ctx.bytes());
    }
    // import_declaration — walk every nested import_spec.
    let mut last: Option<NodeId> = None;
    for spec in collect_specs(node) {
        last = Some(build_import_node(store, spec, ctx.bytes()));
    }
    last.unwrap_or_else(|| empty_import(store, node))
}

/// Walk the named children of an `import_declaration`, collecting every
/// `import_spec` (handles both inline `import "x"` and the block form
/// `import ( "x" "y" )`).
fn collect_specs<'tree>(node: TsNode<'tree>) -> Vec<TsNode<'tree>> {
    let mut out: Vec<TsNode<'tree>> = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        push_specs_from(child, &mut out);
    }
    out
}

/// Append `import_spec` nodes from a single `import_declaration` child.
///
/// Direct `import_spec` children are appended as-is; `import_spec_list`
/// (the parenthesised block form) is descended one level. Anything else
/// is ignored.
fn push_specs_from<'tree>(child: TsNode<'tree>, out: &mut Vec<TsNode<'tree>>) {
    match child.kind() {
        "import_spec" => out.push(child),
        "import_spec_list" => extend_from_spec_list(child, out),
        _ => {}
    }
}

/// Append every `import_spec` named child of an `import_spec_list`.
fn extend_from_spec_list<'tree>(list: TsNode<'tree>, out: &mut Vec<TsNode<'tree>>) {
    let mut cursor = list.walk();
    for c in list.named_children(&mut cursor) {
        if c.kind() == "import_spec" {
            out.push(c);
        }
    }
}

/// Build a single Import node from an `import_spec`.
fn build_import_node(store: &mut CpgWriteBatch, spec: TsNode<'_>, bytes: &[u8]) -> NodeId {
    let path = extract_import_path(spec, bytes);
    let alias = extract_import_alias(spec, bytes);
    let kind_label = classify_import(alias.as_deref());
    let builder = NodeBuilder::new(NodeKind::Import)
        .with_prop("import_kind", intern_string(store, kind_label))
        .with_prop("module_path", intern_string(store, &path))
        .with_prop("source", intern_string(store, &path))
        .with_prop(
            "names_imported",
            Value::String(alias.clone().unwrap_or_default()),
        )
        .with_prop(
            "alias",
            intern_string(store, alias.as_deref().unwrap_or("")),
        )
        .with_prop("range", Value::Range(range_from_ts_range(spec.range())));
    store.push_node(builder)
}

/// Build an empty Import node for an `import ( )` block with no specs.
fn empty_import(store: &mut CpgWriteBatch, node: TsNode<'_>) -> NodeId {
    let builder = NodeBuilder::new(NodeKind::Import)
        .with_prop("import_kind", intern_string(store, "empty"))
        .with_prop("module_path", intern_string(store, ""))
        .with_prop("source", intern_string(store, ""))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Extract the quoted import path from an `import_spec`.
fn extract_import_path(spec: TsNode<'_>, bytes: &[u8]) -> String {
    let path_node = spec.child_by_field_name("path").or_else(|| {
        let mut cursor = spec.walk();
        let found = spec.named_children(&mut cursor).find(|c| {
            matches!(
                c.kind(),
                "interpreted_string_literal" | "raw_string_literal"
            )
        });
        found
    });
    let raw = path_node.map_or("", |n| node_text(n, bytes));
    raw.trim_matches(|c| c == '"' || c == '`').to_owned()
}

/// Extract the alias / dot-import marker / blank-import marker.
fn extract_import_alias(spec: TsNode<'_>, bytes: &[u8]) -> Option<String> {
    let alias = spec.child_by_field_name("name")?;
    Some(node_text(alias, bytes).to_owned())
}

/// Classify the import per Go conventions:
/// - `dot` for `. "fmt"` (current namespace)
/// - `blank` for `_ "init/only"` (side-effect only)
/// - `aliased` for `f "fmt"`
/// - `absolute` for the bare default form
fn classify_import(alias: Option<&str>) -> &'static str {
    match alias {
        Some(".") => "dot",
        Some("_") => "blank",
        Some(_) => "aliased",
        None => "absolute",
    }
}

/// Lift a `comment` token into a [`NodeKind::Comment`].
pub(crate) fn lift_comment(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let text = node_text(node, ctx.bytes());
    let kind_label = classify_comment(text);
    let builder = NodeBuilder::new(NodeKind::Comment)
        .with_prop("text", intern_string(store, text))
        .with_prop("kind", intern_string(store, kind_label))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// `//go:build` and `//go:` directives are tagged so build-tag tooling
/// can distinguish them from ordinary comments without re-parsing text.
fn classify_comment(text: &str) -> &'static str {
    let trimmed = text.trim_start();
    if trimmed.starts_with("//go:build") || trimmed.starts_with("// +build") {
        "build_tag"
    } else if trimmed.starts_with("//go:") {
        "directive"
    } else if text.starts_with("/*") {
        "block"
    } else {
        "line"
    }
}
