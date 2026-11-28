//! Unbounded text conversion of exceptions and caller-controlled values.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend_python::syntax::{children, text, Imports};
use cc_rules::{Rule, RuleContext};
use tree_sitter::Node;

use crate::helpers::{build_finding, BugFindingBlueprint};
use crate::python_calls::{self, ancestors, field, is_scope, name, parameter, unparenthesized};
use crate::python_signatures::Syntax;

const ID: &str = "cc.bug.unbounded_detail_text";
const CONFIDENCE: Confidence = Confidence::new(0.9);

/// Flags diagnostic text that can stringify an arbitrarily large or hostile value.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnboundedDetailTextRule;

impl Rule for UnboundedDetailTextRule {
    fn rule_id(&self) -> &'static str {
        ID
    }

    fn category(&self) -> Category {
        Category::Bug
    }

    fn default_severity(&self) -> Severity {
        Severity::Required
    }

    fn default_confidence(&self) -> Confidence {
        CONFIDENCE
    }

    fn description(&self) -> &'static str {
        "An exception or caller-controlled value is converted to detail text without a bound"
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        python_calls::scan_nodes(
            ctx,
            |_, source| {
                source.contains('{') || ["str", "repr", "format"].iter().any(|s| source.contains(s))
            },
            |node| {
                matches!(node.kind(), "assignment" | "pair" | "keyword_argument")
                    || node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "argument_list")
            },
            |path, source, imports, sink| {
                let syntax = Syntax {
                    path,
                    source,
                    imports,
                    context: ctx,
                };
                check_sink(&syntax, sink)
            },
        )
    }
}

fn check_sink(syntax: &Syntax<'_>, sink: Node<'_>) -> Option<Finding> {
    let source = syntax.source;
    let (destination, value) = match sink.kind() {
        "assignment" => {
            let (target, value) = assigned_sink(sink, syntax.imports)?;
            let label = if target.kind() == "attribute" {
                name(target, source)?
            } else {
                detail_key(target, syntax)?
            };
            (Some(label), value)
        }
        "pair" => (
            Some(detail_key(field(sink, "key")?, syntax)?),
            field(sink, "value")?,
        ),
        "keyword_argument" => (
            Some(text(field(sink, "name")?, source)),
            field(sink, "value")?,
        ),
        _ => (None, sink),
    };
    let input = unbounded_input(value, syntax, 48)?;
    let label = match destination {
        Some(label) if detail_name(label) => label.into(),
        Some(_) => return None,
        None => syntax.detail_argument(sink, detail_name)?,
    };
    Some(build_finding(BugFindingBlueprint {
        rule_id: ID,
        severity: Severity::Required,
        confidence: CONFIDENCE,
        location: python_calls::location(syntax.path, sink),
        headline: format!("`{label}` receives unbounded text from `{input}`"),
        explanation: "String conversion of hostile input can produce huge text or raise while recording the detail.".into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass the original value to the shared plain_text helper with a finite limit, then store the bounded detail.".into(),
        ),
        snippet: text(sink, source).chars().take(180).collect(),
        weight: 3,
    }))
}

fn detail_key<'s>(key: Node<'_>, syntax: &Syntax<'s>) -> Option<&'s str> {
    let key = python_calls::identifier_assignment(key, syntax.imports)
        .and_then(|assignment| field(assignment, "right"))
        .unwrap_or(key);
    let key = unparenthesized(key);
    if key.kind() != "string" {
        return None;
    }
    let mut parts =
        children(key).filter(|node| !matches!(node.kind(), "string_start" | "string_end"));
    let content = parts.next()?;
    (content.kind() == "string_content" && parts.next().is_none())
        .then(|| text(content, syntax.source))
}

fn assigned_sink<'tree>(
    assignment: Node<'tree>,
    imports: &Imports<'_>,
) -> Option<(Node<'tree>, Node<'tree>)> {
    let target = field(assignment, "left")?;
    let destination = match target.kind() {
        "attribute" => target,
        "subscript" => dictionary_key(target, imports)?,
        _ => return None,
    };
    Some((destination, field(assignment, "right")?))
}

fn dictionary_key<'tree>(target: Node<'tree>, imports: &Imports<'_>) -> Option<Node<'tree>> {
    let container = field(target, "value")?;
    let key = field(target, "subscript")?;
    let dictionary = python_calls::identifier_assignment(container, imports)
        .and_then(|assignment| field(assignment, "right"))
        .is_some_and(|value| matches!(value.kind(), "dictionary" | "dictionary_comprehension"));
    (dictionary || key.kind() == "string").then_some(key)
}

fn detail_name(name: &str) -> bool {
    matches!(
        name,
        "detail" | "what" | "why" | "message" | "reason" | "todo"
    )
}

fn unbounded_input<'s>(value: Node<'_>, syntax: &Syntax<'s>, depth: usize) -> Option<&'s str> {
    let remaining = depth.checked_sub(1)?;
    let nested = |node| unbounded_input(node, syntax, remaining);
    let value = unparenthesized(value);
    match value.kind() {
        "identifier" => nested(field(
            python_calls::identifier_assignment(value, syntax.imports)?,
            "right",
        )?),
        "interpolation" | "format_expression" => {
            let expression = field(value, "expression")?;
            risky_name(expression, syntax.source, syntax.imports, remaining)
                .or_else(|| nested(expression))
        }
        "call" => unbounded_call(value, syntax, remaining),
        "subscript" if !has_slice_bound(value) => nested(field(value, "value")?),
        "conditional_expression" => {
            let mut expressions = children(value).filter(|child| child.kind() != "comment");
            nested(expressions.next()?).or_else(|| nested(expressions.last()?))
        }
        "string"
        | "concatenated_string"
        | "binary_operator"
        | "boolean_operator"
        | "tuple"
        | "list" => children(value).find_map(nested),
        "keyword_argument" => nested(field(value, "value")?),
        _ => None,
    }
}

fn unbounded_call<'s>(call: Node<'_>, syntax: &Syntax<'s>, depth: usize) -> Option<&'s str> {
    let Syntax {
        source, imports, ..
    } = *syntax;
    let callee = field(call, "function")?;
    let spelling = name(callee, source).unwrap_or_default();
    let qualified = imports.qualified_name(callee);
    if bounding_name(qualified.as_deref().unwrap_or(spelling))
        || (callee.kind() == "identifier"
            && !imports.has_binding(callee)
            && matches!(
                spelling,
                "len" | "bool" | "int" | "float" | "hash" | "type" | "id"
            ))
    {
        return None;
    }
    let args = field(call, "arguments")?;
    if callee.kind() == "identifier"
        && !imports.has_binding(callee)
        && matches!(spelling, "str" | "repr" | "format")
    {
        let input = children(args).find(|node| node.kind() != "comment")?;
        if let Some(risky) = risky_name(unparenthesized(input), source, imports, depth) {
            return Some(risky);
        }
    }
    let input = field(callee, "object")
        .and_then(|receiver| unbounded_input(receiver, syntax, depth))
        .or_else(|| children(args).find_map(|arg| unbounded_input(arg, syntax, depth)))?;
    let constructs_object = syntax
        .with_definition(callee, &|definition, _| {
            Some(definition.node.kind() == "class_definition")
        })
        .unwrap_or(false);
    (!constructs_object).then_some(input)
}

fn bounding_name(spelling: &str) -> bool {
    let callable = spelling.rsplit('.').next().unwrap_or(spelling);
    let mut words = callable.split('_').peekable();
    while let Some(word) = words.next() {
        if matches!(word, "clip" | "bound" | "bounded" | "truncate" | "shorten")
            || (word == "plain" && words.peek() == Some(&"text"))
        {
            return true;
        }
    }
    false
}

fn risky_name<'s>(
    input: Node<'_>,
    source: &'s str,
    imports: &Imports<'_>,
    depth: usize,
) -> Option<&'s str> {
    let remaining = depth.checked_sub(1)?;
    if input.kind() == "attribute" && name(input, source) == Some("args") {
        return risky_name(field(input, "object")?, source, imports, remaining);
    }
    if input.kind() != "identifier" {
        return None;
    }
    if let Some(assignment) = python_calls::identifier_assignment(input, imports) {
        return risky_name(field(assignment, "right")?, source, imports, remaining);
    }
    let spelling = text(input, source);
    let owner = ancestors(input).find(|node| is_scope(*node));
    let caught = ancestors(input)
        .take_while(|node| Some(*node) != owner)
        .any(|node| caught_as(node, source) == Some(spelling));
    let from_parameter = matches!(spelling, "error" | "exc" | "value" | "payload")
        && owner.is_some_and(|node| parameter(node, spelling, source));
    (caught || from_parameter).then_some(spelling)
}

fn caught_as<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    if node.kind() != "except_clause" {
        return None;
    }
    let alias = field(node, "alias").or_else(|| field(field(node, "value")?, "alias"))?;
    let ident = if alias.kind() == "as_pattern_target" {
        children(alias).next()?
    } else {
        alias
    };
    (ident.kind() == "identifier").then(|| text(ident, source))
}

fn has_slice_bound(node: Node<'_>) -> bool {
    let Some(slice) = field(node, "subscript").filter(|part| part.kind() == "slice") else {
        return false;
    };
    let mut cursor = slice.walk();
    let end = slice
        .children(&mut cursor)
        .skip_while(|part| part.kind() != ":")
        .skip(1)
        .find(|part| part.kind() != "comment");
    end.is_some_and(|part| part.is_named() && unparenthesized(part).kind() != "none")
}
