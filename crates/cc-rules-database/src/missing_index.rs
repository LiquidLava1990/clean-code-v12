//! `cc.db.missing_index` — STUB.
//!
//! Detection requires query-log + EXPLAIN integration that is not
//! available in Phase 4. The probe is registered (so the pack count is
//! stable and downstream wiring tests pass) but unconditionally returns
//! an empty [`Vec`].
//!
//! TODO(phase-5): wire query-log + EXPLAIN.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-10 probe R-DB-MISSING-INDEX (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingIndexRule;

impl Rule for MissingIndexRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.missing_index"
    }
    fn category(&self) -> Category {
        Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "missing index on a hot query column (Phase-4 stub; needs query log)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire query-log + EXPLAIN.
        Vec::new()
    }
}
