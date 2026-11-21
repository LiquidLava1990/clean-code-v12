//! `cc.arch.ownership_gap` — STUB.
//!
//! The real probe scans `CODEOWNERS` and reports every module not
//! covered by an entry. Phase 3 ships the registration shell only;
//! returning `Vec::new()` keeps the rule registered (so kernel
//! tests can verify all five Family-20 probes load) without firing
//! false positives.
//!
//! TODO(phase-4): wire CODEOWNERS parser. Open work:
//! - parse `.github/CODEOWNERS` / `CODEOWNERS` / `docs/CODEOWNERS`
//! - cross-reference globs against every File node's `path` prop
//! - report unmatched files with severity `Required`

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-20 rule R-ARCH-OWNERSHIP-GAP (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct OwnershipGapRule;

impl Rule for OwnershipGapRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.ownership_gap"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "module without a CODEOWNERS entry (stub — phase 4)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-4): wire CODEOWNERS parser. Until the parser
        // ships, returning empty is the correct conservative
        // behaviour: zero false positives.
        Vec::new()
    }
}
