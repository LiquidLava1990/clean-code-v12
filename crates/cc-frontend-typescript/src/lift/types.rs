//! Helpers for extracting source-text-based properties (names, signatures,
//! literal kinds, type parameter lists) from a tree-sitter `Node`.
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
/// The mapping covers the tokens tree-sitter-typescript distinguishes:
/// `string`, `number`, `true` / `false`, `null`, `undefined`,
/// `template_string`, and `regex`.
pub(crate) fn literal_kind_for(node: TsNode<'_>) -> &'static str {
    match node.kind() {
        "string" => "str",
        "number" => "num",
        "true" | "false" => "bool",
        "null" => "null",
        "undefined" => "undefined",
        "template_string" => "template",
        "regex" => "regex",
        _ => "unknown",
    }
}

/// Extract the function name from a `function_declaration`,
/// `method_definition`, or `arrow_function`. Arrow functions are anonymous
/// — they receive the synthetic name `<arrow>` so downstream tooling has
/// something stable to display.
pub(crate) fn function_name(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    if let Some(n) = node.child_by_field_name("name") {
        return node_text(n, source_bytes).to_owned();
    }
    if node.kind() == "arrow_function" {
        return "<arrow>".to_owned();
    }
    String::new()
}

/// Build a one-line "signature" summary for a function (`name(p1, p2)`).
///
/// Used for diagnostics + score visualisations; not a replacement for the
/// real parameter nodes which carry typed defaults.
pub(crate) fn function_signature(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    let name_text = function_display_name(node, source_bytes);
    let params = node
        .child_by_field_name("parameters")
        .map_or(String::new(), |p| node_text(p, source_bytes).to_owned());
    if params.is_empty() {
        format!("{name_text}()")
    } else {
        format!("{name_text}{params}")
    }
}

/// Return a human-readable name for a function-shaped node, defaulting to
/// `<arrow>` for `arrow_function` and `<anonymous>` for everything else
/// without a `name` field.
fn function_display_name(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    node.child_by_field_name("name").map_or_else(
        || {
            if node.kind() == "arrow_function" {
                "<arrow>".to_owned()
            } else {
                "<anonymous>".to_owned()
            }
        },
        |n| node_text(n, source_bytes).to_owned(),
    )
}

/// Truthy iff the function-shaped node carries the `async` modifier.
///
/// The `async` keyword surfaces as an unnamed child token whose text
/// matches `async` for both `function_declaration` and `arrow_function`;
/// `method_definition` exposes it the same way.
pub(crate) fn is_async_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    has_unnamed_token(node, source_bytes, "async")
}

/// Truthy iff the function-shaped node carries the `*` (generator) marker.
pub(crate) fn is_generator_function(node: TsNode<'_>, source_bytes: &[u8]) -> bool {
    has_unnamed_token(node, source_bytes, "*")
}

/// Truthy iff `node` has any unnamed child token whose source text is
/// exactly `target`. Modifier keywords (`async`) and one-shot syntactic
/// markers (`*` for generators) are surfaced as unnamed children by
/// tree-sitter; both `is_async_function` and `is_generator_function`
/// reduce to a single-token presence check, so we keep one canonical
/// implementation.
fn has_unnamed_token(node: TsNode<'_>, source_bytes: &[u8], target: &str) -> bool {
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        if !c.is_named() && node_text(c, source_bytes) == target {
            return true;
        }
    }
    false
}

/// Extract the list of generic type-parameter names from a
/// `type_parameters` node (the field is `type_parameters` on functions,
/// classes, and interfaces).
pub(crate) fn generic_type_param_names(node: TsNode<'_>, source_bytes: &[u8]) -> Vec<String> {
    let Some(params) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "type_parameter")
        .filter_map(|param| type_param_name(param, source_bytes))
        .collect()
}

/// Extract the displayed name of a single `type_parameter` node.
///
/// Prefers the explicit `name` field; falls back to the first named
/// child when the grammar version emits the identifier as a positional
/// child instead.
fn type_param_name(param: TsNode<'_>, source_bytes: &[u8]) -> Option<String> {
    let name_node = param
        .child_by_field_name("name")
        .or_else(|| param.named_child(0))?;
    Some(node_text(name_node, source_bytes).to_owned())
}

/// Heuristic React-component detector.
///
/// A function counts as a React component when:
///
/// 1. its declared name (or the binding identifier of an arrow) starts
///    with an uppercase ASCII letter, AND
/// 2. its body or expression contains a `jsx_element`,
///    `jsx_self_closing_element`, or `jsx_fragment`.
///
/// This is consistent with the React / TS lint rule `react/jsx-pascal-case`
/// and avoids false positives on `PascalCase` helpers that don't return JSX.
pub(crate) fn is_react_component(node: TsNode<'_>, name: &str) -> bool {
    if !starts_with_uppercase(name) {
        return false;
    }
    contains_jsx(node)
}

/// True if `name`'s first byte is an ASCII uppercase letter.
fn starts_with_uppercase(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
}

/// Recursively scan `node` for any JSX-flavoured tree-sitter kind. We bound
/// the walk by the `body` / `return_type` of `node` so we don't walk siblings.
fn contains_jsx(node: TsNode<'_>) -> bool {
    if is_jsx_kind(node.kind()) {
        return true;
    }
    let mut cursor = node.walk();
    for c in node.named_children(&mut cursor) {
        if contains_jsx(c) {
            return true;
        }
    }
    false
}

/// Tree-sitter-typescript node kinds that mean "this is JSX".
fn is_jsx_kind(kind: &str) -> bool {
    matches!(
        kind,
        "jsx_element"
            | "jsx_self_closing_element"
            | "jsx_fragment"
            | "jsx_opening_element"
            | "jsx_expression"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_uppercase_only_ascii() {
        assert!(starts_with_uppercase("Foo"));
        assert!(!starts_with_uppercase("foo"));
        assert!(!starts_with_uppercase(""));
        // Non-ASCII PascalCase doesn't count — React rule is ASCII-only.
        assert!(!starts_with_uppercase("É"));
    }

    #[test]
    fn jsx_kind_recognised() {
        assert!(is_jsx_kind("jsx_element"));
        assert!(is_jsx_kind("jsx_self_closing_element"));
        assert!(!is_jsx_kind("call_expression"));
    }
}
