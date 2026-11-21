//! Lifters for `use_declaration`, `extern_crate_declaration`, attributes,
//! and comments.

use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_frontend::lift_helpers::{intern_string, range_from_ts_range};
use tree_sitter::Node as TsNode;

use crate::lift::context::LiftCtx;
use crate::lift::types::node_text;

/// Lift `use foo::bar` / `extern crate foo` into a [`NodeKind::Import`].
///
/// We capture three pieces: the originating module path (the leading
/// segment), the list of imported names (everything after `::` plus aliases),
/// and an `import_kind` tag (`use` / `extern_crate`).
pub(crate) fn lift_import(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let kind_label = match node.kind() {
        "use_declaration" => "use",
        "extern_crate_declaration" => "extern_crate",
        other => other,
    };
    let (module_path, names) = extract_use_path_and_names(node, ctx.bytes());
    let builder = NodeBuilder::new(NodeKind::Import)
        .with_prop("import_kind", intern_string(store, kind_label))
        .with_prop("module_path", intern_string(store, &module_path))
        .with_prop("names_imported", Value::String(names.join(",")))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Extract `(root_path, imported_names)` from a `use_declaration` /
/// `extern_crate_declaration` by reading the argument child verbatim and
/// then splitting it on `::` and `,` boundaries.
fn extract_use_path_and_names(node: TsNode<'_>, bytes: &[u8]) -> (String, Vec<String>) {
    let arg = node
        .child_by_field_name("argument")
        .or_else(|| node.child_by_field_name("name"));
    let raw = arg.map_or(String::new(), |n| node_text(n, bytes).to_owned());
    parse_use_text(&raw)
}

/// Pure helper: split a `use` argument text into `(root_path, names_list)`.
///
/// `foo::bar::{a, b as c, d}` -> (`foo::bar`, `[a, c, d]`).
/// `foo::bar` -> (`foo`, `[bar]`).
/// `foo` -> (`foo`, `[foo]`).
fn parse_use_text(raw: &str) -> (String, Vec<String>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (String::new(), Vec::new());
    }
    if let Some((root, group)) = split_group(trimmed) {
        return (root, parse_group_names(group));
    }
    if let Some((root, tail)) = trimmed.rsplit_once("::") {
        return (root.to_owned(), vec![alias_name(tail)]);
    }
    (trimmed.to_owned(), vec![alias_name(trimmed)])
}

/// Split `root::{a, b}` into `(root, "a, b")`. Returns `None` if there's no
/// brace group at the tail.
fn split_group(text: &str) -> Option<(String, &str)> {
    let open = text.find('{')?;
    let close = text.rfind('}')?;
    if close <= open {
        return None;
    }
    let prefix = text[..open].trim_end_matches("::").trim();
    Some((prefix.to_owned(), &text[open + 1..close]))
}

/// Parse a comma-separated group body into a list of names, honoring
/// `as` aliases.
fn parse_group_names(group: &str) -> Vec<String> {
    group
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(alias_name)
        .collect()
}

/// Honour `name as alias` — return the alias when present, else the name.
fn alias_name(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .last()
        .map_or_else(|| text.to_owned(), |s| (*s).to_owned())
}

/// Lift an `attribute_item` / `inner_attribute_item` into a
/// [`NodeKind::Decorator`].
pub(crate) fn lift_attribute(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let raw = node_text(node, ctx.bytes());
    let body = raw
        .trim()
        .trim_start_matches("#![")
        .trim_start_matches("#[")
        .trim_end_matches(']')
        .trim();
    let builder = NodeBuilder::new(NodeKind::Decorator)
        .with_prop("expression", intern_string(store, body))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

/// Lift `line_comment` / `block_comment` into a [`NodeKind::Comment`]
/// classified as `line` / `block` plus a `doc` flag for `///` and `//!`.
pub(crate) fn lift_comment(
    ctx: &LiftCtx<'_>,
    store: &mut CpgWriteBatch,
    node: TsNode<'_>,
) -> NodeId {
    let text = node_text(node, ctx.bytes());
    let comment_kind = match node.kind() {
        "block_comment" => "block",
        _ => "line",
    };
    let is_doc = text.starts_with("///") || text.starts_with("//!") || text.starts_with("/**");
    let builder = NodeBuilder::new(NodeKind::Comment)
        .with_prop("text", intern_string(store, text))
        .with_prop("kind", intern_string(store, comment_kind))
        .with_prop("is_doc", Value::Bool(is_doc))
        .with_prop("range", Value::Range(range_from_ts_range(node.range())));
    store.push_node(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_use() {
        let (root, names) = parse_use_text("std::io::Read");
        assert_eq!(root, "std::io");
        assert_eq!(names, vec!["Read".to_owned()]);
    }

    #[test]
    fn parse_grouped_use() {
        let (root, names) = parse_use_text("std::io::{Read, Write as W}");
        assert_eq!(root, "std::io");
        assert_eq!(names, vec!["Read".to_owned(), "W".to_owned()]);
    }

    #[test]
    fn parse_bare_crate() {
        let (root, names) = parse_use_text("serde");
        assert_eq!(root, "serde");
        assert_eq!(names, vec!["serde".to_owned()]);
    }

    #[test]
    fn parse_empty_use() {
        let (root, names) = parse_use_text("");
        assert_eq!(root, "");
        assert!(names.is_empty());
    }
}
