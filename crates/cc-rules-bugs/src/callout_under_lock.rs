//! External calls made while holding a Python lock.

use camino::Utf8Path;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend_python::syntax::{children, preorder, text, Imports};
use cc_rules::{Rule, RuleContext};
use tree_sitter::Node;

use crate::helpers::{build_finding, BugFindingBlueprint};
use crate::python_calls::{self, ancestors, field, is_scope, name, parameter};
use crate::python_signatures::{assignments, direct_definition};

const ID: &str = "cc.bug.callout_under_lock";
const CONFIDENCE: Confidence = Confidence::new(0.9);

/// Flags callbacks and outbound methods inside a lock context.
#[derive(Debug, Default, Clone, Copy)]
pub struct CalloutUnderLockRule;

impl Rule for CalloutUnderLockRule {
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
        "An external callable runs while a lock is held"
    }

    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        python_calls::scan(
            ctx,
            |_, source| source.contains("with") || source.contains("acquire"),
            check_call,
        )
    }
}

fn check_call(
    path: &Utf8Path,
    source: &str,
    imports: &Imports<'_>,
    call: Node<'_>,
) -> Option<Finding> {
    let callee = field(call, "function")?;
    if !is_callout(callee, source) {
        return None;
    }
    let held = |site| {
        let mut locks = enclosing_locks(site, source, imports)
            .chain(manual_locks(site, source, imports))
            .filter(|lock| site == call || !released_before(call, *lock, source, 0))
            .peekable();
        locks.peek().is_some() && !locks.any(|lock| is_lock_operation(callee, lock, source))
    };
    if !held(call) && !helper_call_sites(call, source).any(held) {
        return None;
    }
    Some(build_finding(BugFindingBlueprint {
        rule_id: ID,
        severity: Severity::Required,
        confidence: CONFIDENCE,
        location: python_calls::location(path, call),
        headline: format!("`{}` calls out while a lock is held", text(callee, source)),
        explanation: "The callable can block or re-enter code that needs the same lock.".into(),
        remediation: Remediation::SuggestedRewrite(
            "Copy what the call needs while holding the lock, release it, then call out.".into(),
        ),
        snippet: text(call, source).chars().take(180).collect(),
        weight: 3,
    }))
}

fn is_lock_operation(callee: Node<'_>, lock: Node<'_>, source: &str) -> bool {
    same_reference(callee, lock, source)
        || field(callee, "object").is_some_and(|receiver| same_reference(receiver, lock, source))
}

fn helper_call_sites<'tree>(
    call: Node<'tree>,
    source: &'tree str,
) -> impl Iterator<Item = Node<'tree>> + 'tree {
    let helper = ancestors(call)
        .find(|node| is_scope(*node))
        .filter(|node| node.kind() == "function_definition");
    let method = helper
        .and_then(|node| field(node, "name"))
        .map(|node| text(node, source))
        .filter(|name| name.starts_with('_') && class_method(call, name, source) == helper);
    let class = ancestors(call).find(|node| node.kind() == "class_definition");
    class
        .zip(method)
        .into_iter()
        .flat_map(move |(class, method)| {
            preorder(class).filter(move |site| {
                site.kind() == "call"
                    && field(*site, "function").is_some_and(|callee| {
                        is_own_attribute(callee, source) && name(callee, source) == Some(method)
                    })
                    && ancestors(*site).find(|node| node.kind() == "class_definition")
                        == Some(class)
            })
        })
}

fn enclosing_locks<'tree>(
    call: Node<'tree>,
    source: &'tree str,
    imports: &'tree Imports<'_>,
) -> impl Iterator<Item = Node<'tree>> + 'tree {
    ancestors(call)
        .take_while(|node| !is_scope(*node))
        .filter(move |node| {
            node.kind() == "with_statement"
                && field(*node, "body").is_some_and(|body| body.start_byte() <= call.start_byte())
        })
        .filter_map(|node| children(node).find(|child| child.kind() == "with_clause"))
        .flat_map(children)
        .filter_map(|item| field(item, "value"))
        .filter_map(|value| match value.kind() {
            "as_pattern" => children(value).next().map(python_calls::unparenthesized),
            _ => Some(value),
        })
        .filter(move |node| is_lock(*node, source, imports))
}

fn manual_locks<'tree>(
    site: Node<'tree>,
    source: &'tree str,
    imports: &'tree Imports<'_>,
) -> impl Iterator<Item = Node<'tree>> + 'tree {
    let unconditional = preceding_steps(site).filter_map(expression_call);
    let conditional = statement_ancestors(site).filter_map(|step| {
        let block = step.parent()?;
        let branch = block.parent()?;
        (branch.kind() == "if_statement" && field(branch, "consequence") == Some(block))
            .then(|| field(branch, "condition"))?
    });
    unconditional.chain(conditional).filter_map(move |acquire| {
        let lock = lock_receiver(acquire, "acquire", source)?;
        if !is_lock(lock, source, imports)
            || released_before(site, lock, source, acquire.end_byte())
        {
            return None;
        }
        statement_ancestors(site)
            .flat_map(|step| std::iter::successors(Some(step), Node::next_named_sibling))
            .any(|step| {
                release_position(step, lock, source, true)
                    .is_some_and(|position| position > site.start_byte())
            })
            .then_some(lock)
    })
}

fn statement_ancestors(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::once(node)
        .chain(ancestors(node))
        .take_while(|node| !is_scope(*node))
        .filter(|node| {
            node.parent()
                .is_some_and(|parent| matches!(parent.kind(), "block" | "module"))
        })
}

fn preceding_steps(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    statement_ancestors(node)
        .flat_map(|step| std::iter::successors(step.prev_named_sibling(), Node::prev_named_sibling))
}

fn expression_call(step: Node<'_>) -> Option<Node<'_>> {
    (step.kind() == "expression_statement")
        .then(|| children(step).next().map(python_calls::unparenthesized))?
        .filter(|node| node.kind() == "call")
}

fn lock_receiver<'tree>(call: Node<'tree>, verb: &str, source: &str) -> Option<Node<'tree>> {
    let callee = field(call, "function")?;
    (name(callee, source) == Some(verb)).then(|| field(callee, "object"))?
}

fn released_before(site: Node<'_>, lock: Node<'_>, source: &str, after: usize) -> bool {
    preceding_steps(site).any(|step| {
        step.start_byte() >= after && release_position(step, lock, source, true).is_some()
    })
}

fn release_position(
    step: Node<'_>,
    lock: Node<'_>,
    source: &str,
    follow_helper: bool,
) -> Option<usize> {
    if step.kind() == "try_statement" {
        let finally = children(step).find(|node| node.kind() == "finally_clause")?;
        let body = children(finally).find(|node| node.kind() == "block")?;
        return children(body).find_map(|child| release_position(child, lock, source, false));
    }
    let call = expression_call(step)?;
    if lock_receiver(call, "release", source).is_some_and(|node| same_reference(node, lock, source))
    {
        return Some(call.start_byte());
    }
    let callee = field(call, "function")?;
    if !follow_helper || !is_private_helper(callee, source) {
        return None;
    }
    let method = class_method(callee, name(callee, source)?, source)?;
    children(field(method, "body")?)
        .any(|child| release_position(child, lock, source, false).is_some())
        .then(|| call.end_byte())
}

fn is_lock(node: Node<'_>, source: &str, imports: &Imports<'_>) -> bool {
    let Some(spelling) = name(node, source) else {
        return false;
    };
    if ["lock", "guard", "mutex"]
        .iter()
        .any(|suffix| spelling.to_ascii_lowercase().ends_with(suffix))
    {
        return true;
    }
    let value = match node.kind() {
        "identifier" => python_calls::identifier_assignment(node, imports)
            .and_then(|assignment| field(assignment, "right")),
        _ => attribute_value(node, source),
    };
    value
        .filter(|right| right.kind() == "call")
        .and_then(|right| field(right, "function"))
        .and_then(|constructor| imports.qualified_name(constructor))
        .is_some_and(|constructor| {
            matches!(constructor.as_str(), "threading.Lock" | "threading.RLock")
        })
}

fn is_callout(callee: Node<'_>, source: &str) -> bool {
    let Some(spelling) = name(callee, source) else {
        return false;
    };
    let callback_name = [
        "emit", "sink", "hook", "callback", "handler", "notify", "on_",
    ]
    .iter()
    .any(|hint| spelling.to_ascii_lowercase().contains(hint));
    if callee.kind() == "identifier" {
        return callback_name
            && ancestors(callee)
                .take_while(|node| node.kind() != "class_definition")
                .any(|owner| parameter(owner, spelling, source));
    }
    if field(callee, "object").is_some_and(|receiver| {
        is_own_attribute(receiver, source) && injected_attribute(receiver, source)
    }) {
        return true;
    }
    if is_own_attribute(callee, source) {
        if injected_attribute(callee, source) {
            return true;
        }
        if is_private_helper(callee, source)
            || (callback_name
                && attribute_value(callee, source)
                    .is_some_and(|value| is_private_helper(value, source)))
        {
            return false;
        }
    }
    callback_name
        || matches!(
            spelling,
            "emit" | "publish" | "notify" | "send" | "file" | "handle"
        )
}

fn is_own_attribute(node: Node<'_>, source: &str) -> bool {
    field(node, "object").is_some_and(|receiver| text(receiver, source) == "self")
}

fn is_private_helper(node: Node<'_>, source: &str) -> bool {
    is_own_attribute(node, source)
        && name(node, source).is_some_and(|spelling| {
            spelling.starts_with('_') && class_method(node, spelling, source).is_some()
        })
}

fn class_method<'tree>(node: Node<'tree>, method: &str, source: &str) -> Option<Node<'tree>> {
    let class = ancestors(node).find(|owner| owner.kind() == "class_definition")?;
    direct_definition(field(class, "body")?, method, source)
        .filter(|member| member.kind() == "function_definition")
}

fn attribute_value<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let owner =
        ancestors(node).find(|ancestor| is_scope(*ancestor) || ancestor.kind() == "module")?;
    last_attribute_value(owner, node, source, node.start_byte()).or_else(|| {
        is_own_attribute(node, source).then_some(())?;
        initializer_value(node, source)
            .map(|(_, value)| value)
            .or_else(|| class_attribute_value(node, source))
    })
}

fn class_attribute_value<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let class = ancestors(node).find(|owner| owner.kind() == "class_definition")?;
    let spelling = name(node, source)?;
    assignments(field(class, "body")?)
        .filter_map(|assignment| {
            python_calls::assignment_value(assignment, |target| {
                target.kind() == "identifier" && text(target, source) == spelling
            })
        })
        .last()
}

fn last_attribute_value<'tree>(
    owner: Node<'tree>,
    target: Node<'_>,
    source: &str,
    before: usize,
) -> Option<Node<'tree>> {
    preorder(field(owner, "body").unwrap_or(owner))
        .take_while(|node| node.start_byte() < before)
        .filter(|node| node.kind() == "assignment" && node.end_byte() <= before)
        .filter(|node| {
            ancestors(*node).find(|ancestor| is_scope(*ancestor) || ancestor.kind() == "module")
                == Some(owner)
        })
        .filter_map(|assignment| {
            python_calls::assignment_value(assignment, |left| same_reference(left, target, source))
        })
        .last()
}

fn same_reference(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    match (left.kind(), right.kind()) {
        ("attribute", "attribute") => {
            name(left, source) == name(right, source)
                && field(left, "object")
                    .zip(field(right, "object"))
                    .is_some_and(|(lhs, rhs)| same_reference(lhs, rhs, source))
        }
        _ => text(left, source) == text(right, source),
    }
}

fn initializer_value<'tree>(node: Node<'tree>, source: &str) -> Option<(Node<'tree>, Node<'tree>)> {
    let init = class_method(node, "__init__", source)?;
    let before = if init.start_byte() <= node.start_byte() && node.end_byte() <= init.end_byte() {
        node.start_byte()
    } else {
        usize::MAX
    };
    Some((init, last_attribute_value(init, node, source, before)?))
}

fn injected_attribute(node: Node<'_>, source: &str) -> bool {
    initializer_value(node, source).is_some_and(|(init, value)| {
        value.kind() == "identifier"
            && text(value, source) != "self"
            && parameter(init, text(value, source), source)
    })
}
