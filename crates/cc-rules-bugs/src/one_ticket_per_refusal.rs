//! Repeated fault and ticket filing on a Python refusal path.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend_python::syntax::{children, preorder, text, Imports};
use cc_rules::{Rule, RuleContext};
use tree_sitter::Node;

use crate::helpers::{build_finding, is_test_file_path, BugFindingBlueprint};
use crate::python_calls::{self, ancestors, field, is_scope, name, unparenthesized};
use crate::python_signatures::Syntax;

const ID: &str = "cc.bug.one_ticket_per_refusal";
const CONFIDENCE: Confidence = Confidence::new(0.85);

/// Flags fault or ticket filing on a refusal path without a dedupe guard.
#[derive(Debug, Default, Clone, Copy)]
pub struct OneTicketPerRefusalRule;

impl Rule for OneTicketPerRefusalRule {
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
        "A refusal files a fault or ticket without checking for a duplicate"
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        python_calls::scan(
            ctx,
            |_, source| source.contains("except") || source.contains("else"),
            |path, source, imports, call| {
                let syntax = Syntax {
                    path,
                    source,
                    imports,
                    context: ctx,
                };
                check_call(&syntax, call)
            },
        )
    }
}

fn check_call(syntax: &Syntax<'_>, call: Node<'_>) -> Option<Finding> {
    let source = syntax.source;
    let callee = field(call, "function")?;
    let is_test = is_test_file_path(syntax.path);
    if !filing_call(call, source)
        || !on_refusal_path(call, source)
        || has_dedupe_guard(call, source, syntax.imports)
        || (is_test && verifies_single_filing(call, source))
        || syntax
            .with_definition(callee, &|decl, _| {
                let body = field(decl.node, "body")?;
                Some(persistent_dedupe_before_filing(
                    body,
                    decl.source,
                    decl.imports,
                ))
            })
            .unwrap_or(false)
    {
        return None;
    }
    let severity = if is_test {
        Severity::Nit
    } else {
        Severity::Required
    };
    Some(build_finding(BugFindingBlueprint {
        rule_id: ID,
        severity,
        confidence: CONFIDENCE,
        location: python_calls::location(syntax.path, call),
        headline: format!(
            "`{}` files on a refusal without a dedupe guard",
            text(callee, source)
        ),
        explanation: "Repeating the same refusal can file another ticket for the same cause."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "File one ticket per distinct cause, keyed by the fault code and the place.".into(),
        ),
        snippet: text(call, source).chars().take(180).collect(),
        weight: if severity == Severity::Nit { 0 } else { 3 },
    }))
}

fn filing_call(call: Node<'_>, source: &str) -> bool {
    call.kind() == "call"
        && field(call, "function")
            .and_then(|callee| name(callee, source))
            .is_some_and(|name| {
                matches!(
                    name,
                    "file" | "file_fault" | "ticket" | "report_fault" | "fault"
                )
            })
}

fn verifies_single_filing(call: Node<'_>, source: &str) -> bool {
    let Some(test_try) = direct_try_for_call(call) else {
        return false;
    };
    let Some(body) = test_try.parent() else {
        return false;
    };
    let is_test = body
        .parent()
        .filter(|def| def.kind() == "function_definition")
        .and_then(|def| field(def, "name"))
        .is_some_and(|node| text(node, source).starts_with("test_"));
    is_test
        && preorder(body)
            .filter(|node| filing_call(*node, source))
            .take(2)
            .count()
            == 1
        && children(body)
            .skip_while(|step| step.start_byte() <= test_try.start_byte())
            .any(|step| is_assertion(step, source))
}

fn direct_try_for_call(call: Node<'_>) -> Option<Node<'_>> {
    let step = call
        .parent()
        .filter(|node| node.kind() == "expression_statement")?;
    let handler = step
        .parent()?
        .parent()
        .filter(|node| node.kind() == "except_clause")?;
    handler
        .parent()
        .filter(|node| node.kind() == "try_statement")
}

fn is_assertion(step: Node<'_>, source: &str) -> bool {
    if step.kind() == "assert_statement" {
        return true;
    }
    step.kind() == "expression_statement"
        && children(step)
            .next()
            .filter(|node| node.kind() == "call")
            .and_then(|call| field(call, "function"))
            .is_some_and(|callee| {
                field(callee, "object").is_some_and(|object| text(object, source) == "self")
                    && name(callee, source).is_some_and(|spelling| spelling.starts_with("assert"))
            })
}

fn persistent_dedupe_before_filing(body: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    let mut steps = children(body).filter(|node| node.kind() != "comment");
    while let Some(statement) = steps.next() {
        match statement.kind() {
            "with_statement" => {
                return field(statement, "body")
                    .is_some_and(|block| persistent_dedupe_before_filing(block, source, imports))
            }
            "if_statement" => {
                return verified_recording_guard(statement, steps.next(), source, imports);
            }
            "expression_statement" if is_dedupe_setup(statement, source) => {}
            _ => return false,
        }
    }
    false
}

fn verified_recording_guard(
    guard: Node<'_>,
    next: Option<Node<'_>>,
    source: &str,
    imports: &Imports<'_>,
) -> bool {
    let Some((key, container)) =
        field(guard, "condition").and_then(|test| persistent_membership(test, source, imports))
    else {
        return false;
    };
    let duplicate_returns = field(guard, "consequence").is_some_and(|block| {
        children(block)
            .find(|node| node.kind() != "comment")
            .is_some_and(|step| step.kind() == "return_statement")
    });
    duplicate_returns && next.is_some_and(|step| records_key(step, key, container, source))
}

fn records_key(step: Node<'_>, key: Node<'_>, container: Node<'_>, source: &str) -> bool {
    if step.kind() != "expression_statement" {
        return false;
    }
    let Some(operation) = children(step).next() else {
        return false;
    };
    recorded_key(operation, source).is_some_and(|(object, index)| {
        text(object, source) == text(container, source) && text(index, source) == text(key, source)
    })
}

type KeyedWrite<'tree> = (Node<'tree>, Node<'tree>);

fn recorded_key<'tree>(operation: Node<'tree>, source: &str) -> Option<KeyedWrite<'tree>> {
    match operation.kind() {
        "call" => recorded_call_key(operation, source),
        "assignment" => recorded_assignment_key(operation),
        _ => None,
    }
}

fn recorded_call_key<'tree>(call: Node<'tree>, source: &str) -> Option<KeyedWrite<'tree>> {
    let callee = field(call, "function")?;
    if !matches!(name(callee, source), Some("add" | "append" | "setdefault")) {
        return None;
    }
    let key = first_argument(call)?;
    Some((field(callee, "object")?, key))
}

fn first_argument(call: Node<'_>) -> Option<Node<'_>> {
    let args = field(call, "arguments")?;
    children(args).find(|node| node.kind() != "comment")
}

fn recorded_assignment_key(assignment: Node<'_>) -> Option<KeyedWrite<'_>> {
    field(assignment, "right")?;
    let target = field(assignment, "left").filter(|node| node.kind() == "subscript")?;
    Some((field(target, "value")?, field(target, "subscript")?))
}

fn is_dedupe_setup(step: Node<'_>, source: &str) -> bool {
    let Some(expression) = children(step).next() else {
        return false;
    };
    expression.kind() == "string"
        || (expression.kind() == "assignment"
            && field(expression, "left").is_some_and(|left| left.kind() == "identifier")
            && field(expression, "right").is_some_and(|right| {
                matches!(
                    right.kind(),
                    "identifier" | "attribute" | "tuple" | "expression_list"
                ) || persistent_container(right, source)
            }))
}

fn persistent_membership<'tree>(
    test: Node<'tree>,
    source: &str,
    imports: &Imports<'_>,
) -> Option<(Node<'tree>, Node<'tree>)> {
    if test.kind() != "comparison_operator" {
        return None;
    }
    let mut cursor = test.walk();
    let mut operators = test.children_by_field_name("operators", &mut cursor);
    let operator = operators.next().filter(|op| op.kind() == "in")?;
    if operators.next().is_some() {
        return None;
    }
    let key = children(test).find(|node| node.kind() != "comment")?;
    let container = operator.next_named_sibling()?;
    let value = python_calls::identifier_assignment(container, imports)
        .and_then(|assignment| field(assignment, "right"))
        .unwrap_or(container);
    persistent_container(value, source).then_some((key, container))
}

fn persistent_container(value: Node<'_>, source: &str) -> bool {
    let own_state =
        |attribute| field(attribute, "object").is_some_and(|object| text(object, source) == "self");
    if value.kind() == "attribute" {
        return own_state(value);
    }
    value.kind() == "call"
        && field(value, "function").is_some_and(|callee| {
            name(callee, source) == Some("setdefault")
                && field(callee, "object").is_some_and(own_state)
        })
}

fn on_refusal_path(call: Node<'_>, source: &str) -> bool {
    ancestors(call)
        .take_while(|node| !is_scope(*node))
        .any(|node| match node.kind() {
            "except_clause" => children(node)
                .find(|child| child.kind() == "block")
                .is_some_and(|body| body.start_byte() <= call.start_byte()),
            "else_clause" => node
                .parent()
                .filter(|parent| parent.kind() == "if_statement")
                .is_some_and(|parent| has_refusal_condition(parent, source)),
            _ => false,
        })
}

fn has_refusal_condition(statement: Node<'_>, source: &str) -> bool {
    field(statement, "condition").is_some_and(|node| refusal_condition(node, source))
        || children(statement)
            .filter(|child| child.kind() == "elif_clause")
            .any(|clause| {
                field(clause, "condition").is_some_and(|node| refusal_condition(node, source))
            })
}

fn refusal_condition(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "identifier" | "attribute" => name(node, source).is_some_and(|spelling| {
            spelling.to_ascii_lowercase().split('_').any(|word| {
                matches!(
                    word,
                    "ok" | "okay"
                        | "allow"
                        | "allowed"
                        | "accept"
                        | "accepted"
                        | "refusal"
                        | "refuse"
                        | "refused"
                        | "deny"
                        | "denied"
                        | "reject"
                        | "rejected"
                        | "valid"
                        | "approve"
                        | "approved"
                        | "permitted"
                        | "success"
                        | "succeeded"
                        | "verdict"
                        | "check"
                )
            })
        }),
        "call" => field(node, "function").is_some_and(|callee| refusal_condition(callee, source)),
        "boolean_operator"
        | "comparison_operator"
        | "not_operator"
        | "parenthesized_expression" => {
            children(node).any(|child| refusal_condition(child, source))
        }
        _ => false,
    }
}

fn has_dedupe_guard(call: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    ancestors(call)
        .take_while(|node| !is_scope(*node))
        .filter(|node| node.kind() == "block")
        .any(|block| {
            guarded_branch(block, source, imports)
                || earlier_guard(block, call.start_byte(), source, imports)
        })
}

fn guarded_branch(block: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    let Some(parent) = block.parent() else {
        return false;
    };
    match parent.kind() {
        "if_statement" | "elif_clause" | "while_statement" => {
            field(parent, "condition").is_some_and(|test| dedupe_test(test, source, imports))
        }
        "else_clause" => {
            let Some(statement) = parent.parent().filter(|node| node.kind() == "if_statement")
            else {
                return false;
            };
            field(statement, "condition").is_some_and(|test| dedupe_test(test, source, imports))
                || children(statement)
                    .filter(|node| node.kind() == "elif_clause")
                    .any(|clause| {
                        field(clause, "condition")
                            .is_some_and(|test| dedupe_test(test, source, imports))
                    })
        }
        _ => false,
    }
}

fn earlier_guard(block: Node<'_>, before: usize, source: &str, imports: &Imports<'_>) -> bool {
    children(block)
        .take_while(|statement| statement.end_byte() <= before)
        .filter(|statement| statement.kind() == "if_statement")
        .any(|statement| {
            field(statement, "condition").is_some_and(|test| dedupe_test(test, source, imports))
                && field(statement, "consequence").is_some_and(|body| {
                    children(body).any(|step| {
                        matches!(
                            step.kind(),
                            "return_statement"
                                | "continue_statement"
                                | "break_statement"
                                | "raise_statement"
                        )
                    })
                })
        })
}

fn dedupe_test(node: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    match node.kind() {
        "call" => field(node, "function").is_some_and(|callee| {
            name(callee, source).is_some_and(|spelling| {
                spelling.starts_with('_')
                    && spelling
                        .split('_')
                        .any(|word| matches!(word, "new" | "seen" | "first"))
            })
        }),
        "identifier" | "attribute" => name(node, source).is_some_and(|spelling| {
            spelling
                .to_ascii_lowercase()
                .split('_')
                .any(|word| matches!(word, "seen" | "filed" | "ticket" | "tickets"))
        }),
        "comparison_operator" => {
            let mut cursor = node.walk();
            let mut membership = node
                .children_by_field_name("operators", &mut cursor)
                .filter(|op| matches!(op.kind(), "in" | "not in"))
                .peekable();
            if membership.peek().is_some() {
                return membership.any(|op| {
                    op.next_named_sibling()
                        .is_some_and(|set| collection_is_updated(set, source, imports))
                });
            }
            children(node).any(|child| dedupe_test(child, source, imports))
        }
        "boolean_operator" | "not_operator" | "parenthesized_expression" => {
            children(node).any(|child| dedupe_test(child, source, imports))
        }
        _ => false,
    }
}

fn collection_is_updated(container: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    let container = unparenthesized(container);
    let owner = ancestors(container).find(|node| is_scope(*node));
    let class = owner.and_then(|node| {
        ancestors(node)
            .find(|parent| is_scope(*parent))
            .filter(|parent| parent.kind() == "class_definition")
    });
    let shared = class.filter(|class| {
        let receiver = field(container, "object").map(|node| text(node, source));
        receiver == Some("self")
            || receiver.is_some()
                && receiver == field(*class, "name").map(|node| text(node, source))
    });
    let root = shared
        .or(owner)
        .unwrap_or_else(|| ancestors(container).last().unwrap_or(container));
    preorder(root).any(|operation| {
        let Some((target, _)) = recorded_key(operation, source) else {
            return false;
        };
        let scope = ancestors(operation).find(|node| is_scope(*node));
        let same_class = shared.is_some_and(|class| {
            scope == Some(class)
                || scope.and_then(|node| ancestors(node).find(|parent| is_scope(*parent)))
                    == Some(class)
        });
        (scope == owner || same_class)
            && text(target, source) == text(container, source)
            && python_calls::identifier_assignment(target, imports)
                == python_calls::identifier_assignment(container, imports)
    })
}
