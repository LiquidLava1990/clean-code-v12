//! `cc.test.flaky_iteration` — loop over time/random/uuid + assertion inside.
//!
//! Heuristic: every [`NodeKind::Loop`] inside a test function whose body
//! contains BOTH a non-deterministic Call (time / random / uuid) AND an
//! assertion Call fires. Rolling-the-dice-N-times-and-asserting is the
//! canonical flake recipe.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_descendant_of, is_test_file_path, location_from_node,
    TestDesignFindingBlueprint, ASSERT_CALLEES, NON_DETERMINISTIC_CALLEES,
};

/// Family-28 probe `cc.test.flaky_iteration`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FlakyIterationRule;

impl Rule for FlakyIterationRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.flaky_iteration"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "loop body asserts on non-deterministic source — flake-by-design"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Loop) {
            if let Some(finding) = check_loop(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_loop(ctx: &RuleContext<'_>, loop_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, loop_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let (has_assert, has_nondet) = scan_loop_body(ctx, loop_id);
    if !(has_assert && has_nondet) {
        return None;
    }
    let location = location_from_node(ctx.batch, loop_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.flaky_iteration",
        severity: Severity::Required,
        confidence: Confidence::new(0.75),
        location,
        headline: "loop asserts on a non-deterministic source".to_owned(),
        explanation: "This loop body calls a time / random / uuid source AND an \
             assertion. Rolling the dice N times inside a test cannot \
             pin a stable behaviour — every CI run plays a fresh game. \
             The result is a flaky test that passes locally and fails \
             on the runner (or vice-versa)."
            .to_owned(),
        remediation: Remediation::SuggestedRewrite(
            "Seed the random source explicitly, freeze the clock, or \
             move the loop's expectation to a property-based testing \
             framework (proptest / hypothesis / fast-check) that records \
             counter-examples instead of probabilistically passing."
                .into(),
        ),
        snippet: String::new(),
        weight: 4,
    }))
}

/// Returns `(has_assertion, has_nondeterministic_call)` for every Call
/// inside the loop body.
fn scan_loop_body(ctx: &RuleContext<'_>, loop_id: NodeId) -> (bool, bool) {
    let mut has_assert = false;
    let mut has_nondet = false;
    for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
        if !is_descendant_of(ctx.batch, call.id, loop_id) {
            continue;
        }
        let text = callee_text(ctx.batch, call.id);
        if ASSERT_CALLEES.iter().any(|n| text.contains(n)) {
            has_assert = true;
        }
        if NON_DETERMINISTIC_CALLEES.iter().any(|n| text.contains(n)) {
            has_nondet = true;
        }
        if has_assert && has_nondet {
            return (true, true);
        }
    }
    (has_assert, has_nondet)
}
