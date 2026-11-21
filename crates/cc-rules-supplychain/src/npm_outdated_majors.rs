//! `cc.supplychain.npm_outdated_majors` — STUB.
//!
//! Detection requires resolving every dependency in `package.json` /
//! `package-lock.json` against deps.dev (or the npm registry) to learn
//! which majors are GA. That ingest is not available in Phase 6. The
//! probe is registered (so the pack count is stable and downstream
//! wiring tests pass) but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-7): wire deps.dev API for major-version-skew.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-32 probe R-SUPPLYCHAIN-NPM-OUTDATED-MAJORS (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct NpmOutdatedMajorsRule;

impl Rule for NpmOutdatedMajorsRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.npm_outdated_majors"
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
        "npm dependency more than one major behind latest GA (stub; needs deps.dev)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-7): wire deps.dev API for major-version-skew.
        Vec::new()
    }
}
