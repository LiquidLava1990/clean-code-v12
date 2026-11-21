//! Helpers for extracting source-text-based properties (names, signatures,
//! literal kinds, lifetimes, where-clauses) from a tree-sitter `Node`.
//!
//! Pure read-only helpers — none of these touch the [`cc_cpg::CpgWriteBatch`].

use tree_sitter::Node as TsNode;

/// Extract the text slice for `node` from `source_bytes`, falling back to
/// an empty string if the byte range is outside `source_bytes` (which
/// shouldn't happen for trees produced from the same source).
pub(crate) fn node_text<'a>(node: TsNode<'_>, source_bytes: &'a [u8]) -> &'a str {
    node.utf8_text(source_bytes).unwrap_or("")
}

/// Returns the literal `kind` we record on a [`cc_cpg::NodeKind::Literal`].
///
/// Maps tree-sitter-rust literal token names to the schema-canonical
/// short-form used by every frontend.
pub(crate) fn literal_kind_for(node: TsNode<'_>) -> &'static str {
    match node.kind() {
        "integer_literal" => "int",
        "float_literal" => "float",
        "boolean_literal" => "bool",
        "char_literal" => "char",
        "string_literal" => "str",
        "raw_string_literal" => "raw",
        _ => "unknown",
    }
}

/// Build a one-line "signature" summary for a `function_item` /
/// `function_signature_item` (`name(params)` or `name<T>(params) -> ret`).
///
/// Used for diagnostics + score visualisations; not a replacement for the
/// real parameter nodes which carry typed defaults.
pub(crate) fn function_signature(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map_or("<anonymous>", |n| node_text(n, source_bytes));
    let params = node
        .child_by_field_name("parameters")
        .map_or(String::new(), |p| node_text(p, source_bytes).to_owned());
    let ret = node
        .child_by_field_name("return_type")
        .map(|r| format!(" -> {}", node_text(r, source_bytes)))
        .unwrap_or_default();
    if params.is_empty() {
        format!("{name}(){ret}")
    } else {
        format!("{name}{params}{ret}")
    }
}

/// Truthy iff the function-item carries the `async` keyword in its
/// modifiers child. Tree-sitter-rust models async/unsafe/const as unnamed
/// keyword children of `function_modifiers`.
pub(crate) fn is_async_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    has_modifier(node, source_bytes, "async")
}

/// Truthy iff the function-item carries the `unsafe` keyword.
pub(crate) fn is_unsafe_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    has_modifier(node, source_bytes, "unsafe")
}

/// Truthy iff the function-item carries the `const` keyword.
pub(crate) fn is_const_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    has_modifier(node, source_bytes, "const")
}

/// Common driver: walks `function_modifiers` (when present) and immediate
/// unnamed children of the function node looking for a keyword token whose
/// text equals `keyword`.
fn has_modifier(node: TsNode<'_>, source_bytes: &[u8], keyword: &str) -> bool {
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        if c.kind() == "function_modifiers" && modifiers_contain(c, source_bytes, keyword) {
            return true;
        }
        if !c.is_named() && node_text(c, source_bytes) == keyword {
            return true;
        }
    }
    false
}

/// Scan the immediate children of a `function_modifiers` node for a
/// keyword token whose source text equals `keyword`.
fn modifiers_contain(modifiers: TsNode<'_>, source_bytes: &[u8], keyword: &str) -> bool {
    // Bind the iterator-with-cursor to a local so the cursor outlives the
    // iterator (tree_sitter cursors borrow from `modifiers`).
    let mut cursor = modifiers.walk();
    let mut iter = modifiers.children(&mut cursor);
    iter.any(|m| node_text(m, source_bytes) == keyword)
}

/// Collect the lifetimes declared on a function's `type_parameters` block.
///
/// Returns the list of lifetime names (with the leading `'`) — empty when the
/// function is not generic. Type parameter names + const generics are skipped.
pub(crate) fn declared_lifetimes(node: TsNode<'_>, source_bytes: &[u8]) -> Vec<String> {
    let Some(generics) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut cursor = generics.walk();
    let mut out: Vec<String> = Vec::new();
    for child in generics.named_children(&mut cursor) {
        // tree-sitter-rust 0.23 wraps lifetimes in `lifetime_parameter`; older
        // grammars surfaced bare `lifetime` nodes. Accept both for forward
        // compatibility.
        let lifetime_node = if child.kind() == "lifetime_parameter" {
            child.child_by_field_name("name").or(Some(child))
        } else if child.kind() == "lifetime" {
            Some(child)
        } else {
            None
        };
        if let Some(lt) = lifetime_node {
            out.push(node_text(lt, source_bytes).to_owned());
        }
    }
    out
}

/// Collect the textual where-clause predicates on a function-item.
///
/// Each `where_predicate` is rendered back from source text (preserving the
/// original whitespace / formatting), giving a faithful round-trip of the
/// constraint.
pub(crate) fn where_clauses(node: TsNode<'_>, source_bytes: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "where_clause" {
            return where_predicates(child, source_bytes);
        }
    }
    Vec::new()
}

/// Walk a `where_clause` collecting one entry per `where_predicate`.
fn where_predicates(clause: TsNode<'_>, source_bytes: &[u8]) -> Vec<String> {
    let mut cursor = clause.walk();
    let mut out: Vec<String> = Vec::new();
    for c in clause.named_children(&mut cursor) {
        if c.kind() == "where_predicate" {
            out.push(node_text(c, source_bytes).trim().to_owned());
        }
    }
    out
}

/// Extract the `Self` type for an `impl_item` — the type the `impl` block
/// targets, e.g. `Foo<T>` in `impl<T> Bar for Foo<T> { ... }`.
pub(crate) fn impl_self_type(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    node.child_by_field_name("type")
        .map_or(String::new(), |n| node_text(n, source_bytes).to_owned())
}

/// Read the `visibility_modifier` child source text, if any.
///
/// Tree-sitter-rust attaches a `visibility_modifier` node as an immediate
/// child of `function_item` / `struct_item` / `enum_item` / `trait_item` /
/// `union_item` / `impl_item` / `const_item` / `static_item` whenever the
/// item carries a `pub`-form modifier. We return the raw source text so
/// `cc_frontend::visibility::rust_visibility` can classify it.
pub(crate) fn visibility_modifier_text<'a>(
    node: TsNode<'_>,
    source_bytes: &'a [u8],
) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            return Some(node_text(child, source_bytes));
        }
    }
    None
}

/// Map a Rust `class`-style item kind onto the schema-canonical short tag
/// used in `Class.kind` (`struct` / `enum` / `iface` / `union`).
///
/// Unknown inputs fall back to `unknown` rather than `struct` so a misrouted
/// dispatch shows up immediately in graph queries instead of silently
/// pretending to be a struct.
pub(crate) fn class_kind_for(ts_kind: &str) -> &'static str {
    match ts_kind {
        "struct_item" => "struct",
        "enum_item" => "enum",
        "trait_item" => "iface",
        "union_item" => "union",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_kind_mapping() {
        assert_eq!(class_kind_for("struct_item"), "struct");
        assert_eq!(class_kind_for("enum_item"), "enum");
        assert_eq!(class_kind_for("trait_item"), "iface");
        assert_eq!(class_kind_for("union_item"), "union");
        assert_eq!(class_kind_for("garbage"), "unknown");
    }

    #[test]
    fn literal_kind_mapping() {
        // Build a minimal parser to get nodes with the right kinds. We can't
        // construct TsNode directly, so we round-trip through a parse.
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("grammar");
        let src = "fn f() { let _ = 1; let _ = 1.0; let _ = true; let _ = \"x\"; }";
        let tree = parser.parse(src, None).expect("parse");
        let mut found = std::collections::BTreeSet::new();
        walk_collect_kinds(tree.root_node(), &mut found);
        assert!(found.contains("integer_literal"));
        assert!(found.contains("float_literal"));
        assert!(found.contains("boolean_literal"));
        assert!(found.contains("string_literal"));
    }

    fn walk_collect_kinds(node: TsNode<'_>, out: &mut std::collections::BTreeSet<&'static str>) {
        out.insert(node.kind());
        let mut cursor = node.walk();
        for c in node.children(&mut cursor) {
            walk_collect_kinds(c, out);
        }
    }
}
