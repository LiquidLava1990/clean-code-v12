//! `cc.test.tests_the_mock` — every assertion in the test targets a
//! mock / stub / fake / spy, never the real impl.
//!
//! Phase-4 simplification: walk every test function (selected by
//! [`crate::helpers::is_test_file_path`] + [`looks_like_test_name`] /
//! [`function_has_test_attr`]). Within the function subtree, collect
//! every Call we recognise as an assertion (per
//! [`crate::helpers::ASSERT_CALLEES`]). If at least one assertion
//! exists AND every assertion's "target" looks like a mock / fake /
//! stub / spy (substring match against
//! [`crate::helpers::MOCK_NAME_NEEDLES`]) — fire.
//!
//! "Target" is the receiver / argument text the frontend stamped onto
//! the assertion's Call node — we look at `receiver`, `target`,
//! `argument`, and the callee text itself. Frontends that don't expose
//! these stay silent rather than misclassify.
//!
//! Phase-5 will tighten this with `PDG_DATA` edges so we can ask "does
//! the asserted value flow through any non-mock symbol?" instead of
//! string-matching call-site argument text.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, callee_text_opt, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_has_test_attr, is_test_file_path,
    location_from_node, looks_like_test_name, TestsFindingBlueprint, ASSERT_CALLEES,
    MOCK_NAME_NEEDLES,
};

/// Family-8 probe R-TEST-TESTS-THE-MOCK.
#[derive(Debug, Default, Clone, Copy)]
pub struct TestsTheMockRule;

impl Rule for TestsTheMockRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.tests_the_mock"
    }
    fn category(&self) -> Category {
        Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "every assertion targets a mock / stub / fake / spy"
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
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("");
    if !looks_like_test_name(name) && !function_has_test_attr(ctx.batch, fn_id) {
        return None;
    }
    let assertions = collect_assertion_targets(ctx, fn_id);
    if assertions.is_empty() {
        // No assertions at all — that is `assertion_free`'s job.
        return None;
    }
    if !assertions.iter().all(|t| target_is_mock(t)) {
        return None;
    }
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TestsFindingBlueprint {
        rule_id: "cc.test.tests_the_mock",
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("test `{name}` only asserts on mock objects"),
        explanation: format!(
            "Every assertion inside `{name}` targets a value whose name \
             contains mock / fake / stub / spy. The test verifies the \
             mock's recorded behaviour, not the system under test — so \
             it cannot detect a regression in the real implementation."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add at least one assertion against the real return value or \
             observable state of the system under test. Use the mock for \
             collaborator inputs, not as the assertion target."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 3,
    }))
}

/// Collect the assertion-target text of every assertion call inside
/// the function subtree.
fn collect_assertion_targets(ctx: &RuleContext<'_>, fn_id: NodeId) -> Vec<String> {
    let mut out = Vec::new();
    for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
        if !call_in_function(ctx, call.id, fn_id) {
            continue;
        }
        let Some(callee) = callee_text_opt(ctx.batch, call.id) else {
            continue;
        };
        if !ASSERT_CALLEES.iter().any(|needle| callee.contains(needle)) {
            continue;
        }
        out.push(target_text(ctx, call.id, &callee));
    }
    out
}

/// Build a string we can scan for mock-name needles. We sweep the
/// receiver / target / argument slots and fall back to the callee text.
fn target_text(ctx: &RuleContext<'_>, call_id: NodeId, callee: &str) -> String {
    let mut buf = String::new();
    for key in ["receiver", "target", "argument", "args", "first_arg"] {
        if let Some(value) = string_prop(ctx.batch, call_id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    if buf.is_empty() {
        buf.push_str(callee);
    }
    buf
}

fn target_is_mock(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    MOCK_NAME_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

fn call_in_function(ctx: &RuleContext<'_>, call_id: NodeId, fn_id: NodeId) -> bool {
    let mut cursor = call_id;
    for _ in 0..256_u16 {
        let Some(parent) = ast_parent(ctx.batch, cursor) else {
            return false;
        };
        if parent == fn_id {
            return true;
        }
        cursor = parent;
    }
    false
}
