//! `cc.test.shared_setup_in_assertion` — no Arrange-Act-Assert separation.
//!
//! Heuristic: count assertion vs non-assertion Call descendants of a
//! test function. If the ratio of non-assertion Calls (setup / act)
//! exceeds 70% AND the function has at least 5 calls AND the last
//! Call by source order IS an assertion, the test fails the AAA shape.
//!
//! Rationale: a healthy test reads "arrange → act → assert" with the
//! arrange phase short and the assertion at the end. A test where the
//! first 10 lines are all setup and only the very last line is an
//! assertion is doing too many things — split it or extract the setup
//! into a fixture.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind, range_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_descendant_of, is_test_function, location_from_node,
    TestDesignFindingBlueprint, ASSERT_CALLEES,
};

/// Family-28 probe `cc.test.shared_setup_in_assertion`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SharedSetupInAssertionRule;

/// Minimum total Call count before the rule fires. Below this we have
/// no signal — short tests are fine.
const MIN_CALLS: usize = 5;

/// Threshold: pre-assertion Calls must be > 70% of total to fire.
const PRE_ASSERTION_THRESHOLD_PCT: u32 = 70;

impl Rule for SharedSetupInAssertionRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.shared_setup_in_assertion"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.55)
    }
    fn description(&self) -> &'static str {
        "test lacks Arrange-Act-Assert separation — too much setup before the assertion"
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
    let calls = collect_calls_in_function(ctx, fn_id);
    if calls.len() < MIN_CALLS {
        return None;
    }
    let (pre_assertion, total, last_is_assertion) = score_call_layout(ctx, &calls);
    if !last_is_assertion {
        return None;
    }
    let pct = pre_assertion.saturating_mul(100) / total.max(1);
    if pct <= PRE_ASSERTION_THRESHOLD_PCT {
        return None;
    }
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.shared_setup_in_assertion",
        severity: Severity::Nit,
        confidence: Confidence::new(0.55),
        location,
        headline: format!("test `{name}` mixes setup and assertion"),
        explanation: format!(
            "{pct}% of the {total} calls inside `{name}` execute before \
             the final assertion. The Arrange-Act-Assert pattern keeps \
             setup short (extract into a fixture) and the act + assert \
             phases tightly co-located. Tests with heavy inline setup \
             are slow to read and slow to debug."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract the setup into a `beforeEach` / `setUp` / fixture / \
             helper function so each test reads as: arrange (one line), \
             act (one line), assert (one or more lines)."
                .into(),
        ),
        snippet: name,
        weight: 1,
    }))
}

/// Collect every Call descendant of `fn_id` ordered by source position.
fn collect_calls_in_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Vec<(NodeId, u32)> {
    let mut out: Vec<(NodeId, u32)> = nodes_of_kind(ctx.batch, NodeKind::Call)
        .filter(|c| is_descendant_of(ctx.batch, c.id, fn_id))
        .map(|c| {
            let line = range_prop(ctx.batch, c.id, "range").map_or(0, |r| r.start.line);
            (c.id, line)
        })
        .collect();
    out.sort_by_key(|(_, line)| *line);
    out
}

/// Returns `(pre_assertion_call_count, total_call_count, last_call_is_assertion)`.
fn score_call_layout(ctx: &RuleContext<'_>, calls: &[(NodeId, u32)]) -> (u32, u32, bool) {
    let total = u32::try_from(calls.len()).unwrap_or(u32::MAX);
    let mut pre_assertion = 0_u32;
    let mut last_is_assertion = false;
    let mut seen_assertion = false;
    for (idx, (id, _)) in calls.iter().enumerate() {
        let is_assert = call_is_assertion(ctx, *id);
        if !seen_assertion && !is_assert {
            pre_assertion = pre_assertion.saturating_add(1);
        }
        if is_assert {
            seen_assertion = true;
        }
        if idx + 1 == calls.len() {
            last_is_assertion = is_assert;
        }
    }
    (pre_assertion, total, last_is_assertion)
}

fn call_is_assertion(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    let text = callee_text(ctx.batch, call_id);
    ASSERT_CALLEES.iter().any(|needle| text.contains(needle))
}
