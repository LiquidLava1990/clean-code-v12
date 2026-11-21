//! `cc.deploy.stale_flag` — STUB.
//!
//! Detection requires walking flag-evaluation history: a flag whose
//! `is_enabled('foo')` call has not appeared in the diff for 30+ days
//! is the canonical "stale flag" pattern (port of Uber's piranha). The
//! single-batch CPG has no view of the commit graph. The probe is
//! registered so the pack count is stable but unconditionally returns
//! an empty [`Vec`].
//!
//! TODO(phase-5): wire flag-history scanner (port piranha pattern).

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-13 probe R-DEPLOY-STALE-FLAG (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct StaleFlagRule;

impl Rule for StaleFlagRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.stale_flag"
    }
    fn category(&self) -> Category {
        Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "feature flag with no recent eval (Phase-4 stub; needs git history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire flag-history scanner (port piranha pattern).
        Vec::new()
    }
}
