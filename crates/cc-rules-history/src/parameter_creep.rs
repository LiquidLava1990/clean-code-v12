//! `cc.rot.parameter_creep` — STUB.
//!
//! Detection requires cross-revision symbol-diff (parameter list
//! growing monotonically over time). Not available in Phase 4.
//!
//! TODO(phase-5): wire cross-revision symbol diff.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-18 probe R-ROT-PARAMETER-CREEP (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ParameterCreepRule;

impl Rule for ParameterCreepRule {
    fn rule_id(&self) -> &'static str {
        "cc.rot.parameter_creep"
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
        "function parameter list grows monotonically (Phase-4 stub; needs git history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire symbol-diff walker.
        Vec::new()
    }
}
