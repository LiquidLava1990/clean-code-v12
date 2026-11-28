//! Syntax-backed call scanning for Python bug probes.

use camino::Utf8Path;
use cc_cpg::NodeKind;
use cc_finding::{Finding, Location, Position};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_frontend::LanguageFrontend;
use cc_frontend_python::syntax::{children, preorder, text, Imports};
use cc_frontend_python::PythonFrontend;
use cc_rules::RuleContext;
use tree_sitter::Node;

pub(crate) fn scan(
    ctx: &RuleContext<'_>,
    applies: impl Fn(&Utf8Path, &str) -> bool,
    check: impl Fn(&Utf8Path, &str, &Imports<'_>, Node<'_>) -> Option<Finding>,
) -> Vec<Finding> {
    scan_nodes(ctx, applies, |node| node.kind() == "call", check)
}

pub(crate) fn scan_nodes(
    ctx: &RuleContext<'_>,
    applies: impl Fn(&Utf8Path, &str) -> bool,
    select: impl Fn(Node<'_>) -> bool,
    check: impl Fn(&Utf8Path, &str, &Imports<'_>, Node<'_>) -> Option<Finding>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in nodes_of_kind(ctx.batch, NodeKind::File) {
        let Some(path) = string_prop(ctx.batch, file.id, "path").map(Utf8Path::new) else {
            continue;
        };
        if path.extension() != Some("py") {
            continue;
        }
        let Ok(source) = std::str::from_utf8(ctx.source.get(path)) else {
            continue;
        };
        if !applies(path, source) {
            continue;
        }
        let Ok(tree) = PythonFrontend::new().parse(source) else {
            continue;
        };
        let root = tree.root_node();
        let imports = Imports::new(root, source);
        out.extend(
            preorder(root)
                .filter(|node| select(*node))
                .filter_map(|node| check(path, source, &imports, node)),
        );
    }
    out
}

pub(crate) fn location(path: &Utf8Path, call: Node<'_>) -> Location {
    let start = call.start_position();
    let end = call.end_position();
    Location {
        file: path.to_owned(),
        start: Position::new(
            start.row as u32 + 1,
            start.column as u32 + 1,
            call.start_byte() as u32,
        ),
        end: Position::new(
            end.row as u32 + 1,
            end.column as u32 + 1,
            call.end_byte() as u32,
        ),
        node_id: None,
        function_qualified_name: None,
    }
}

pub(crate) fn field<'tree>(node: Node<'tree>, key: &str) -> Option<Node<'tree>> {
    node.child_by_field_name(key).map(unparenthesized)
}

pub(crate) fn unparenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = children(node).find(|child| child.kind() != "comment") else {
            break;
        };
        node = inner;
    }
    node
}

pub(crate) fn name<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    match node.kind() {
        "identifier" => Some(text(node, source)),
        "attribute" => Some(text(field(node, "attribute")?, source)),
        _ => None,
    }
}

pub(crate) fn ancestors(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(node.parent(), Node::parent)
}

pub(crate) fn is_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "class_definition" | "lambda"
    )
}

pub(crate) fn parameter(owner: Node<'_>, spelling: &str, source: &str) -> bool {
    field(owner, "parameters").is_some_and(|params| {
        children(params)
            .filter_map(parameter_name)
            .any(|node| text(node, source) == spelling)
    })
}

pub(crate) fn parameter_name(param: Node<'_>) -> Option<Node<'_>> {
    match param.kind() {
        "identifier" => Some(param),
        "default_parameter" | "typed_default_parameter" => field(param, "name"),
        "typed_parameter" => children(param).find(|child| child.kind() == "identifier"),
        _ => None,
    }
}

pub(crate) fn identifier_assignment<'tree>(
    node: Node<'tree>,
    imports: &Imports<'_>,
) -> Option<Node<'tree>> {
    if node.kind() != "identifier" {
        return None;
    }
    let end = imports.local_binding_end(node)?;
    let root = ancestors(node).last()?;
    let leaf = root.descendant_for_byte_range(end.checked_sub(1)?, end)?;
    ancestors(leaf)
        .take_while(|ancestor| ancestor.end_byte() == end)
        .find(|ancestor| {
            ancestor.kind() == "assignment"
                && field(*ancestor, "left").is_some_and(|left| left.kind() == "identifier")
        })
}

pub(crate) fn assignment_value(
    assignment: Node<'_>,
    matches_target: impl Fn(Node<'_>) -> bool,
) -> Option<Node<'_>> {
    let left = field(assignment, "left")?;
    let right = field(assignment, "right")?;
    if matches_target(left) {
        return Some(right);
    }
    if !matches!(left.kind(), "pattern_list" | "tuple_pattern")
        || !matches!(right.kind(), "expression_list" | "tuple")
    {
        return None;
    }
    children(left)
        .filter(|node| node.kind() != "comment")
        .zip(children(right).filter(|node| node.kind() != "comment"))
        .find_map(|(target, value)| matches_target(target).then_some(value))
}
