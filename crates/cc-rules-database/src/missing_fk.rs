//! `cc.db.missing_fk` — STUB.
//!
//! Detection requires cross-referencing model classes with the migration
//! files in the same directory tree. That cross-reference is too
//! speculative without a persistent CPG (Phase 5+); a heuristic on a
//! single-file batch would generate noise. The probe is registered so
//! the pack count is stable, but unconditionally returns an empty
//! [`Vec`].
//!
//! TODO(phase-5): cross-reference Model classes with migration FK rows
//! once the persistent CPG store lands.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-10 probe R-DB-MISSING-FK (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingFkRule;

impl Rule for MissingFkRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.missing_fk"
    }
    fn category(&self) -> Category {
        Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "model relationship without DB foreign-key constraint (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): cross-reference model classes with migration files.
        Vec::new()
    }
}
