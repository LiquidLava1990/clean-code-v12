//! `cc.meta.refactor_drift` — touched-file health regression ratchet.
//!
//! # Phase-1 status: stub.
//!
//! The full implementation requires baseline-vs-current health-score
//! diff, which lands in `cc-baseline` (Phase-1 W3). The rule is
//! registered now so downstream tooling can see its slug; the runner
//! returns an empty `Vec<Finding>` until the baseline crate exists.
//!
//! TODO(phase-1-W3): wire baseline diff via `cc_baseline::ScoreDiff`.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Tier-0 forever rule R-REFACTOR (touched-file health ratchet).
#[derive(Debug, Default, Clone, Copy)]
pub struct RefactorDriftRule;

impl Rule for RefactorDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.refactor_drift"
    }
    fn category(&self) -> Category {
        Category::Meta
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "touched-file health regressed since baseline (refactor on contact)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-1-W3): wire baseline diff
        Vec::new()
    }
}
