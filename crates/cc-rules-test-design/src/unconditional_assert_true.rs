//! `cc.test.unconditional_assert_true` — assertion that always passes.
//!
//! Catches `assert!(true)` (Rust), `expect(true).toBe(true)` (jest),
//! `self.assertTrue(True)` (unittest), and `t.Errorf("ok")` patterns
//! whose argument string evaluates to a literal truthy constant.
//!
//! Heuristic: every assertion-shaped Call inside a test file whose
//! argument text equals one of `TAUTOLOGIES` (after lowercase + whitespace
//! trim) fires. Matching the *argument text* avoids the need to lift
//! literal Boolean values from the AST — frontends inconsistently
//! surface those, but they all stamp a textual `arguments` /
//! `args` / `argument` slot we can read.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    TestDesignFindingBlueprint, ASSERT_CALLEES,
};

/// Family-28 probe `cc.test.unconditional_assert_true`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconditionalAssertTrueRule;

const TAUTOLOGIES: &[&str] = &[
    "true",
    "true, true",
    "true == true",
    "1 == 1",
    "1, 1",
    "True",
    "True, True",
];

impl Rule for UnconditionalAssertTrueRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.unconditional_assert_true"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "assertion always passes — `assert!(true)` / `expect(true).toBe(true)`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, call_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let callee = callee_text(ctx.batch, call_id);
    if !ASSERT_CALLEES.iter().any(|needle| callee.contains(needle)) {
        return None;
    }
    if !argument_text_is_tautology(ctx, call_id) {
        return None;
    }
    let location = location_from_node(ctx.batch, call_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.unconditional_assert_true",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "assertion always passes".to_owned(),
        explanation: "This assertion compares a literal truthy constant against \
             itself; it can never fail. Either remove it (the test \
             gains nothing) or replace with an assertion that pins the \
             real behaviour under test."
            .to_owned(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the literal-vs-literal assertion with one that \
             evaluates the system under test, or delete the test if no \
             behaviour is being verified."
                .into(),
        ),
        snippet: callee,
        weight: 4,
    }))
}

fn argument_text_is_tautology(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    for key in ["arguments", "args", "argument", "first_arg", "expression"] {
        if let Some(value) = string_prop(ctx.batch, call_id, key) {
            let normalised = value
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            if TAUTOLOGIES
                .iter()
                .any(|t| normalised.eq_ignore_ascii_case(t))
            {
                return true;
            }
        }
    }
    false
}
