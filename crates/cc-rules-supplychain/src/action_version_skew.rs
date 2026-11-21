//! `cc.supplychain.action_version_skew` — STUB.
//!
//! Detection requires diffing workflow files between branches (e.g.
//! `main` vs the PR branch) to know which actions actually moved
//! versions. That cross-branch view is not available in Phase 6. The
//! probe is registered (so the pack count is stable and downstream
//! wiring tests pass) but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-7): wire workflow file diff between branches.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-32 probe R-SUPPLYCHAIN-ACTION-VERSION-SKEW (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ActionVersionSkewRule;

impl Rule for ActionVersionSkewRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.action_version_skew"
    }
    fn category(&self) -> Category {
        Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "GitHub Action moved versions between base and PR (stub; needs cross-branch diff)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-7): wire workflow file diff between branches.
        Vec::new()
    }
}
