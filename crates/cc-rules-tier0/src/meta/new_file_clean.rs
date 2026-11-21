//! `cc.meta.new_file_clean` — every newly-added file must be Tier-0
//! GREEN before it lands.
//!
//! # Phase-1 status: stub.
//!
//! Full implementation needs git-blame integration to detect "new"
//! files in the current commit. The rule is registered now so
//! downstream config layers can already pin its slug; the runner
//! returns an empty `Vec<Finding>` until git-blame plumbing lands.
//!
//! TODO(phase-1-W3): wire git-blame via `cc_baseline::GitBlame`.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Tier-0 forever rule R-CLEAN-1 (new file gate).
#[derive(Debug, Default, Clone, Copy)]
pub struct NewFileCleanRule;

impl Rule for NewFileCleanRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.new_file_clean"
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
        "newly-added file must be Tier-0 GREEN from line 1"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-1-W3): wire git-blame
        Vec::new()
    }
}
