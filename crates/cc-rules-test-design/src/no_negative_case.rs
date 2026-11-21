//! `cc.test.no_negative_case` — Phase-6 STUB.
//!
//! Detection requires a whole-program test-name companion check:
//! for every test `test_do_X_works`, look for a sibling test
//! `test_do_X_rejects_invalid` / `test_do_X_errors` / `test_do_X_panics`.
//! Per-batch scans see only one file at a time, which is insufficient.
//
// TODO(phase-7): wire test-name companion check. Steps:
//   1. Aggregate every test-function name across the entire crawl into
//      a project-level table on `RuleContext::project`.
//   2. Group names by their `do_X` stem (strip `test_` prefix + the
//      `_works` / `_happy` / `_returns_X` tail).
//   3. For each stem with no companion negative-case test, emit one
//      finding at the location of the positive test.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-28 probe `cc.test.no_negative_case` (Phase-6 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNegativeCaseRule;

impl Rule for NoNegativeCaseRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.no_negative_case"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "test has no negative / error / rejection companion"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-6 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
