//! `cc.ci.flaky_test_history` — STUB.
//!
//! Detection requires CI run-history ingestion (per-test pass/fail
//! ratios over time) that is not available in Phase 4. The probe is
//! registered (so the pack count is stable and downstream wiring tests
//! pass) but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-5): wire CI history ingestion + flake-rate computation.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-17 probe R-CI-FLAKY-TEST-HISTORY (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct FlakyTestHistoryRule;

impl Rule for FlakyTestHistoryRule {
    fn rule_id(&self) -> &'static str {
        "cc.ci.flaky_test_history"
    }
    fn category(&self) -> Category {
        Category::Ci
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "test flakes across recent CI runs (Phase-4 stub; needs CI history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire CI run history.
        Vec::new()
    }
}
