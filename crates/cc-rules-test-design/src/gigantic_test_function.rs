//! `cc.test.gigantic_test_function` — test body > 100 logical lines.
//!
//! Tunable separately from Tier-0 `cc.shape.fn_length` (50 LOC default).
//! Tests legitimately carry slightly more boilerplate than production
//! functions (arrange phase) but a 100-line test is doing too many
//! things — split it.
//!
//! Heuristic: read the function's `range` property, count distinct
//! source lines spanned, fire when count > [`MAX_TEST_LINES`].

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_function, location_from_node, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.gigantic_test_function`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GiganticTestFunctionRule;

/// Maximum logical-line span before the rule fires. Separately tunable
/// from `cc.shape.fn_length` (50) per the OSS-delta requirement.
const MAX_TEST_LINES: u32 = 100;

impl Rule for GiganticTestFunctionRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.gigantic_test_function"
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
        "test function body exceeds the 100-LOC test ceiling"
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
    let lines = function_line_span(ctx.batch, fn_id)?;
    if lines <= MAX_TEST_LINES {
        return None;
    }
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.gigantic_test_function",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("test `{name}` is {lines} lines (max {MAX_TEST_LINES})"),
        explanation: format!(
            "Test functions ceiling is {MAX_TEST_LINES} logical lines — \
             higher than production's 50-line ceiling because the \
             arrange phase carries weight, but `{name}` blows past even \
             that allowance at {lines} lines. A test this large \
             exercises multiple behaviours; the failure message points \
             at one symptom but the root cause could be any of them."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Split the test into focused per-behaviour cases. Extract \
             the common arrange phase into a helper / fixture so each \
             test case stays readable end-to-end."
                .into(),
        ),
        snippet: name,
        weight: 2,
    }))
}

fn function_line_span(batch: &CpgWriteBatch, fn_id: NodeId) -> Option<u32> {
    let range = range_prop(batch, fn_id, "range")?;
    Some(
        range
            .end
            .line
            .saturating_sub(range.start.line)
            .saturating_add(1),
    )
}
