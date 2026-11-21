//! `cc.test.assertion_count_zero` — test with zero assertion-call descendants.
//!
//! Tighter cousin of `cc.test.assertion_free` from `cc-rules-tests`:
//! this variant treats the Rust `?` operator as an assertion-equivalent
//! (the propagated `Err` itself is the failure signal in a `#[test] fn
//! foo() -> Result<…>`), so a function whose body is one big `?` chain
//! is silent here even though the broader Family-8 rule may fire.
//!
//! Family-8 `cc.test.assertion_free` keeps the broad gate; this rule
//! exists to satisfy linters / users who want a tighter signal that
//! Result-returning Rust tests ARE assertions.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_descendant_of, is_test_function, location_from_node,
    TestDesignFindingBlueprint, ASSERT_CALLEES,
};

/// Family-28 probe `cc.test.assertion_count_zero`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssertionCountZeroRule;

impl Rule for AssertionCountZeroRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.assertion_count_zero"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test has zero assertion calls and no `?` operator"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let (path, name) = is_test_function(ctx.batch, fn_id)?;
    if function_has_assertion(ctx, fn_id) {
        return None;
    }
    if function_has_try_propagation(ctx, fn_id) {
        return None;
    }
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.assertion_count_zero",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("test `{name}` has zero assertion calls"),
        explanation: format!(
            "Test `{name}` calls no assertion API and contains no `?` \
             operator the Rust testing harness could interpret as a \
             failure. The test cannot fail; it provides regression \
             coverage in name only."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add at least one assertion that pins the behaviour under \
             test, or — for Rust — return `Result<(), E>` and propagate \
             errors with `?` so a failed step actually fails the test."
                .into(),
        ),
        snippet: name,
        weight: 3,
    }))
}

fn function_has_assertion(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    nodes_of_kind(ctx.batch, NodeKind::Call).any(|call| {
        is_descendant_of(ctx.batch, call.id, fn_id) && {
            let text = callee_text(ctx.batch, call.id);
            ASSERT_CALLEES.iter().any(|needle| text.contains(needle))
        }
    })
}

/// Detect the Rust `?` operator. Frontends lift `expr?` differently —
/// some emit a `Try` node, some stamp `is_try=true` on the parent
/// expression, some leave a textual `?` in the call's `signature`.
/// Either signal counts.
fn function_has_try_propagation(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    if has_try_node_descendant(ctx, fn_id) {
        return true;
    }
    nodes_of_kind(ctx.batch, NodeKind::Call)
        .any(|call| is_descendant_of(ctx.batch, call.id, fn_id) && call_uses_try(ctx, call.id))
}

fn has_try_node_descendant(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    nodes_of_kind(ctx.batch, NodeKind::Try).any(|t| is_descendant_of(ctx.batch, t.id, fn_id))
}

fn call_uses_try(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    for key in ["signature", "expression", "qualified", "callee_ref"] {
        if let Some(value) = string_prop(ctx.batch, call_id, key) {
            if value.ends_with('?') || value.contains(".unwrap_or_else") {
                return true;
            }
        }
    }
    false
}
