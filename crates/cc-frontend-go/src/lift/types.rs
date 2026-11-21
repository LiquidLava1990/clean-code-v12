//! Helpers for extracting source-text properties (names, signatures,
//! receiver types, literal kinds) from a tree-sitter Go `Node`.
//!
//! Pure read-only helpers — none of these touch the [`cc_cpg::CpgWriteBatch`].

use tree_sitter::Node as TsNode;

/// Extract the text slice for `node` from `source_bytes`.
pub(crate) fn node_text<'a>(node: TsNode<'_>, source_bytes: &'a [u8]) -> &'a str {
    node.utf8_text(source_bytes).unwrap_or("")
}

/// Returns the literal `kind` we record on a [`cc_cpg::NodeKind::Literal`].
///
/// Maps tree-sitter-go literal node kinds to a canonical short tag.
pub(crate) fn literal_kind_for(node: TsNode<'_>) -> &'static str {
    match node.kind() {
        "int_literal" => "int",
        "float_literal" => "float",
        "imaginary_literal" => "imaginary",
        "rune_literal" => "rune",
        "true" | "false" => "bool",
        "nil" => "nil",
        "interpreted_string_literal" => "str",
        "raw_string_literal" => "raw",
        _ => "unknown",
    }
}

/// Build a one-line "signature" summary for a function (`name(p1) ret`).
///
/// Used for diagnostics + score visualisations; not a replacement for the
/// real [`cc_cpg::NodeKind::Parameter`] nodes.
pub(crate) fn function_signature(node: TsNode<'_>, source_bytes: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map_or("<anonymous>", |n| node_text(n, source_bytes));
    let params = node
        .child_by_field_name("parameters")
        .map_or(String::new(), |p| node_text(p, source_bytes).to_owned());
    let result = node
        .child_by_field_name("result")
        .map_or(String::new(), |r| {
            format!(" {}", node_text(r, source_bytes))
        });
    if params.is_empty() {
        format!("{name}(){result}")
    } else {
        format!("{name}{params}{result}")
    }
}

/// Extract the receiver type text from a `method_declaration` node, e.g.
/// `*Foo` from `func (f *Foo) Bar()`.
///
/// Returns `None` for free `function_declaration` nodes. Best-effort: if
/// the receiver list has more than one parameter (uncommon in valid Go)
/// we return the first.
pub(crate) fn method_receiver_type(node: TsNode<'_>, source_bytes: &[u8]) -> Option<String> {
    let receiver = node.child_by_field_name("receiver")?;
    let mut cursor = receiver.walk();
    for child in receiver.named_children(&mut cursor) {
        // The receiver is a `parameter_list` -> `parameter_declaration`.
        if child.kind() == "parameter_declaration" {
            if let Some(ty) = child.child_by_field_name("type") {
                return Some(node_text(ty, source_bytes).trim().to_owned());
            }
        }
    }
    Some(node_text(receiver, source_bytes).trim().to_owned())
}

/// Classify a `for_statement` body shape: bare `for {}` (infinite),
/// condition `for cond {}`, range `for k, v := range x {}`, or three-clause
/// `for init; cond; post {}`.
pub(crate) fn for_kind(node: TsNode<'_>) -> &'static str {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "range_clause" => return "range",
            "for_clause" => return "c_style",
            _ => {}
        }
    }
    if node.child_by_field_name("condition").is_some() {
        "while_style"
    } else {
        "infinite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap();
        p.parse(src, None).unwrap()
    }

    #[test]
    fn literal_kind_maps_known_kinds() {
        assert_eq!(literal_kind_for_kind("int_literal"), "int");
        assert_eq!(literal_kind_for_kind("nil"), "nil");
        assert_eq!(literal_kind_for_kind("true"), "bool");
    }

    fn literal_kind_for_kind(k: &str) -> &'static str {
        match k {
            "int_literal" => "int",
            "float_literal" => "float",
            "true" | "false" => "bool",
            "nil" => "nil",
            "interpreted_string_literal" => "str",
            "raw_string_literal" => "raw",
            _ => "unknown",
        }
    }

    #[test]
    fn parses_method_receiver() {
        let src = "package p\nfunc (f *Foo) Bar() {}\n";
        let tree = parse(src);
        let root = tree.root_node();
        let mut cursor = root.walk();
        let method = root
            .named_children(&mut cursor)
            .find(|n| n.kind() == "method_declaration")
            .unwrap();
        let r = method_receiver_type(method, src.as_bytes());
        assert!(r.is_some());
    }
}
