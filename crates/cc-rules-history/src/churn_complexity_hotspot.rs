//! `cc.rot.churn_complexity_hotspot` — STUB.
//!
//! Detection requires git-blame + cyclomatic-complexity correlation
//! across history. Not available in Phase 4.
//!
//! TODO(phase-5): wire git-blame walker + complexity correlation.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-18 probe R-ROT-CHURN-COMPLEXITY-HOTSPOT (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ChurnComplexityHotspotRule;

impl Rule for ChurnComplexityHotspotRule {
    fn rule_id(&self) -> &'static str {
        "cc.rot.churn_complexity_hotspot"
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
        "high-churn high-complexity hotspot (Phase-4 stub; needs git history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire git-blame walker.
        Vec::new()
    }
}
