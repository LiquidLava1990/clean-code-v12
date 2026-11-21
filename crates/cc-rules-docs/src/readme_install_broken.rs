//! `cc.docs.readme_install_broken` — STUB.
//!
//! Detection requires actually running the install commands embedded
//! in `README.md` fenced code blocks (a `runme`-style executor) and
//! observing exit codes. Phase 5 ships the rule registration only —
//! Phase 6 wires the executor.
//!
//! TODO(future): wire runme execution.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-16 probe R-DOCS-README-INSTALL-BROKEN (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadmeInstallBrokenRule;

impl Rule for ReadmeInstallBrokenRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.readme_install_broken"
    }
    fn category(&self) -> Category {
        Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "README install commands fail to execute (Phase-5 stub; needs runme)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(future): wire runme execution.
        Vec::new()
    }
}
