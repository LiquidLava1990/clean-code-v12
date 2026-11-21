//! `cc.contract.postcondition_missing` — public function returning a
//! value where the return value isn't checked at any caller in the same
//! batch.
//!
//! Phase-2 status: STUB. The full check needs the caller-side `Call`
//! node with the use site of the return value, which the Phase-2 CPG
//! does not yet model. Registers the rule_id so the registry test
//! recognises it and emits zero findings until Phase 3 wires use-tracking.
//!
//! TODO(phase-3): walk every CG_CALLS edge incoming to a public fn and
//! confirm the call site assigns / matches / asserts on the return.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Probe `cc.contract.postcondition_missing` (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct PostconditionMissingRule;

impl Rule for PostconditionMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.contract.postcondition_missing"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "public fn return value is not checked at any caller (stub — Phase 3)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-3): wire use-of-return tracking via PDG_DATA edges.
        Vec::new()
    }
}
