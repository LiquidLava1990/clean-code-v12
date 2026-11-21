//! `cc.api.schema_vs_db_drift` — STUB.
//!
//! Detection requires cross-referencing ORM model definitions
//! (`SQLAlchemy` / Django / Diesel / GORM) with the migration files in
//! the same directory tree. The two sides live in separate batches and
//! the cross-reference is too speculative without a persistent CPG
//! store (Phase 5+). The probe is registered so the pack count is
//! stable, but unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-5): cross-reference ORM-model columns with migration
//! `CREATE TABLE` / `ALTER TABLE` rows once the persistent CPG store
//! lands.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-9 probe R-API-SCHEMA-VS-DB-DRIFT (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct SchemaVsDbDriftRule;

impl Rule for SchemaVsDbDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.schema_vs_db_drift"
    }
    fn category(&self) -> Category {
        Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "ORM schema disagrees with migration / DB schema (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): cross-reference ORM models with migration files.
        Vec::new()
    }
}
