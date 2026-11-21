//! `cc.ci.hook_bypass_in_history` — STUB.
//!
//! Detection requires a git-log walker that surfaces commits authored
//! with `--no-verify`. The git plumbing is not yet exposed through
//! [`cc_rules::RuleContext`] and is deferred to Phase 5.
//!
//! TODO(phase-5): wire git-log walker.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-17 probe R-CI-HOOK-BYPASS-IN-HISTORY (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct HookBypassInHistoryRule;

impl Rule for HookBypassInHistoryRule {
    fn rule_id(&self) -> &'static str {
        "cc.ci.hook_bypass_in_history"
    }
    fn category(&self) -> Category {
        Category::Ci
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "git history contains hook-bypass commits (Phase-4 stub; needs git-log walker)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire git-log walker.
        Vec::new()
    }
}
