//! `cc.rot.partial_rewrites` — STUB.
//!
//! Detection requires cross-revision diffing of large structural
//! refactors that landed only partially. Not available in Phase 4.
//!
//! TODO(phase-5): wire cross-revision diff.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-18 probe R-ROT-PARTIAL-REWRITES (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct PartialRewritesRule;

impl Rule for PartialRewritesRule {
    fn rule_id(&self) -> &'static str {
        "cc.rot.partial_rewrites"
    }
    fn category(&self) -> Category {
        Category::Rot
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "abandoned partial rewrite leaves V1 + V2 coexisting (Phase-4 stub; needs git history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire cross-revision diff.
        Vec::new()
    }
}
