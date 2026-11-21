//! Helpers for extracting source-text-based properties (names, signatures,
//! literal kinds) from a tree-sitter `Node`.
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
/// The mapping covers the common cases tree-sitter-python distinguishes via
/// its `string` / `integer` / `float` / `true` / `false` / `none` tokens
/// plus the prefix-bearing string variants (`f"..."`, `b"..."`, `r"..."`).
pub(crate) fn literal_kind_for(node: TsNode<'_>, source_bytes: &[u8]) -> &'static str {
    match node.kind() {
        "integer" => "int",
        "float" => "float",
        "true" | "false" => "bool",
        "none" => "none",
        "string" => string_subkind(node, source_bytes),
        _ => "unknown",
    }
}

/// Inspect a `string` token's leading prefix to classify the subkind.
///
/// Handles single-letter (`f"..."` / `b"..."` / `r"..."`) and the common
/// two-letter combos (`rb"..."` / `fr"..."`). Order-insensitive on the
/// `r` modifier per Python lexical rules.
pub(crate) fn string_subkind(node: TsNode<'_>, source_bytes: &[u8]) -> &'static str {
    let text = node_text(node, source_bytes);
    let prefix: String = text
        .chars()
        .take_while(|c| !matches!(c, '\'' | '"'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    classify_prefix(&prefix)
}

/// Map a lowercased prefix string to its literal subkind.
fn classify_prefix(prefix: &str) -> &'static str {
    if prefix.is_empty() {
        return "str";
    }
    let has_f = prefix.contains('f');
    let has_b = prefix.contains('b');
    let has_r = prefix.contains('r');
    match (has_f, has_b, has_r) {
        (true, _, _) => "fstring",
        (false, true, _) => "bytes",
        (false, false, true) => "raw",
        _ => "str",
    }
}

/// Build a one-line "signature" summary for a function (`name(p1, p2)`).
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
    if params.is_empty() {
        format!("{name}()")
    } else {
        format!("{name}{params}")
    }
}

/// Truthy iff the function-definition node carries the `async` modifier.
pub(crate) fn is_async_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    let mut cursor = node.walk();
    let mut found = false;
    for c in node.children(&mut cursor) {
        // The `async` keyword surfaces as an unnamed child token whose text
        // matches `async`. Tree-sitter-python doesn't expose a field for it.
        if !c.is_named() && node_text(c, source_bytes) == "async" {
            found = true;
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_string_prefix_variants() {
        assert_eq!(classify_prefix(""), "str");
        assert_eq!(classify_prefix("u"), "str");
        assert_eq!(classify_prefix("r"), "raw");
        assert_eq!(classify_prefix("b"), "bytes");
        assert_eq!(classify_prefix("rb"), "bytes");
        assert_eq!(classify_prefix("br"), "bytes");
        assert_eq!(classify_prefix("f"), "fstring");
        assert_eq!(classify_prefix("rf"), "fstring");
        assert_eq!(classify_prefix("fr"), "fstring");
    }
}
