//! `cc.test.flaky` — test passes / fails non-deterministically.
//!
//! Phase-4 STUB. Detection requires test-execution history across
//! multiple runs — a single static scan cannot prove non-determinism.
//! The rule is registered for surface stability and will start
//! firing once the kernel exposes a `FlakeHistory` resource on
//! `RuleContext`.
//
// TODO(phase-5): wire flake-history accumulator. Steps:
//   1. CLI / CI emits per-test pass/fail records into a small redb
//      table keyed by `(rule_id, file, name, run_id)`.
//   2. ScoreEngine streams the last N runs into a `FlakeHistory`
//      handle attached to `RuleContext::project`.
//   3. This rule reads the handle, computes pass-rate per test, and
//      fires when 0.05 < pass_rate < 0.95 over ≥ 10 runs.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-8 probe R-TEST-FLAKY (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct FlakyRule;

impl Rule for FlakyRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.flaky"
    }
    fn category(&self) -> Category {
        Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "test passes or fails non-deterministically across runs"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-4 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
