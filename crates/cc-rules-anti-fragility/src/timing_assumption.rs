//! `cc.fragile.timing_assumption` — sleep-based test, time-based logic.
//!
//! Heuristic: in test files, walk every [`NodeKind::Call`] and report
//! any callee that resolves to a sleep / blocking-delay primitive
//! (see [`SLEEP_CALLEES`]). Sleeping in tests is the canonical
//! anti-fragility smell — the test passes locally, then flakes under
//! CI load because the wall-clock budget runs out.
//!
//! Non-test files are silent — production sleeps belong to other
//! rules (perf, concurrency).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, AntiFragilityFindingBlueprint, SLEEP_CALLEES,
};

/// Family-23 probe `cc.fragile.timing_assumption`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TimingAssumptionRule;

impl Rule for TimingAssumptionRule {
    fn rule_id(&self) -> &'static str {
        "cc.fragile.timing_assumption"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Fragile
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test contains a sleep / blocking-delay call (timing assumption)"
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

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    if !matches_sleep_callee(&text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    if looks_like_rule_pack_source(&path) {
        // Rule-pack tests embed sleep callee strings as fixture data
        // (e.g. `Value::String("time.sleep".into())` to drive the
        // sync-in-async / timing-assumption probes). Scanning rule-pack
        // source flags the detector for owning the shape it scans for.
        // Skip until the AST detector lands.
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(AntiFragilityFindingBlueprint {
        rule_id: "cc.fragile.timing_assumption",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "test sleeps to wait for an event — flake risk".into(),
        explanation: "Tests that block on `sleep` / `setTimeout` pass locally \
             and flake under CI load. The wall-clock budget the test assumes \
             evaporates the moment another job shares the runner."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the sleep with deterministic synchronisation: a barrier, \
             a mock clock, an `await` on the actual signal, or a polling \
             helper with a generous timeout that asserts the *condition* \
             rather than the elapsed time."
                .into(),
        ),
        snippet: text,
        weight: 2,
    }))
}

fn matches_sleep_callee(text: &str) -> bool {
    SLEEP_CALLEES.iter().any(|needle| text.contains(needle))
}
