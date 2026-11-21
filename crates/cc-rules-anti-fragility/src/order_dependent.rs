//! `cc.fragile.order_dependent` — test passes only in declaration order.
//!
//! Phase-4 STUB. Detecting order-dependence requires running each test
//! file twice — once in declaration order, once randomized — and
//! diffing the pass/fail set. That signal lives in the test runner, not
//! the static CPG.
//!
//! TODO(phase-5): wire test-runner randomized-order detection. The
//! probe will subscribe to a `TestRunReport` once `cc-runtime` exposes
//! one, compare per-test outcomes across two ordered runs, and emit a
//! finding for every test whose outcome flips.
//!
//! Until then this rule registers (so the pack ships four probes) and
//! returns an empty [`Vec`] on every batch — never a false positive,
//! never a false negative against a signal it cannot see.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-23 probe `cc.fragile.order_dependent` (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct OrderDependentRule;

impl Rule for OrderDependentRule {
    fn rule_id(&self) -> &'static str {
        "cc.fragile.order_dependent"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Fragile
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "test passes only when run in declaration order (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire test-runner randomized-order detection.
        // Static CPG cannot observe inter-test ordering; the signal
        // arrives via `TestRunReport` once `cc-runtime` exposes one.
        Vec::new()
    }
}
