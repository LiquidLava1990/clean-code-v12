//! `cc.ci.slow_test` — STUB.
//!
//! Detection requires per-test runtime data (junit XML / pytest-durations
//! ingestion) that is not available in Phase 4. The probe is registered
//! but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-5): wire runtime-data ingestion.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-17 probe R-CI-SLOW-TEST (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct SlowTestRule;

impl Rule for SlowTestRule {
    fn rule_id(&self) -> &'static str {
        "cc.ci.slow_test"
    }
    fn category(&self) -> Category {
        Category::Ci
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "test exceeds slow-runtime threshold (Phase-4 stub; needs runtime data)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire junit / pytest-durations ingestion.
        Vec::new()
    }
}
