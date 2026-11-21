//! `cc.deploy.big_bang_migration` — STUB.
//!
//! Detection requires git-history awareness: a single PR that touches
//! multiple migration files (the "big bang" pattern) is the failure
//! mode. The single-batch CPG has no view of the working-tree diff or
//! the commit graph. The probe is registered so the pack count is
//! stable but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-5): wire git-history walker for multi-migration-touch
//! detection.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-13 probe R-DEPLOY-BIG-BANG (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct BigBangMigrationRule;

impl Rule for BigBangMigrationRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.big_bang_migration"
    }
    fn category(&self) -> Category {
        Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "multi-step migration in a single PR (Phase-4 stub; needs git history)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire git-history walker for multi-migration-touch detection.
        Vec::new()
    }
}
