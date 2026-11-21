//! `cc.db.missing_backfill` — `NOT NULL` added without a `DEFAULT`.
//!
//! Heuristic: walk migration files (same path matcher as
//! [`crate::locking_migration`]) and scan source bytes for
//! `ALTER TABLE ... ADD COLUMN ... NOT NULL` statements that DO NOT
//! carry a `DEFAULT` clause. Without a default, the migration fails
//! mid-deploy as soon as the first existing row is touched, leaving
//! production in a half-migrated state.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_migration_path, location_for_file, DatabaseFindingBlueprint,
};

/// Family-10 probe R-DB-MISSING-BACKFILL.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingBackfillRule;

impl Rule for MissingBackfillRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.missing_backfill"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "ADD COLUMN ... NOT NULL on a migration without a DEFAULT clause"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(raw) = string_prop(ctx.batch, file_id, "path") else {
        return;
    };
    let path = Utf8PathBuf::from(raw);
    if !is_migration_path(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if !looks_like_missing_backfill(line) {
            continue;
        }
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        out.push(emit(&path, line_no, line.trim()));
    }
}

/// True iff the line looks like an unguarded `ADD COLUMN … NOT NULL`
/// without a `DEFAULT` clause.
fn looks_like_missing_backfill(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    if !upper.contains("ALTER TABLE") {
        return false;
    }
    if !upper.contains("ADD COLUMN") {
        return false;
    }
    if !upper.contains("NOT NULL") {
        return false;
    }
    !upper.contains("DEFAULT")
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(DatabaseFindingBlueprint {
        rule_id: "cc.db.missing_backfill",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.8),
        location,
        headline: "`ADD COLUMN … NOT NULL` without `DEFAULT`".to_owned(),
        explanation: format!(
            "Migration `{}` adds a `NOT NULL` column without a `DEFAULT` \
             clause. The deploy will succeed against an empty table and \
             fail the moment it hits a populated one — the engine cannot \
             materialise a value for existing rows. The result is a \
             half-applied migration in production.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Two-step: (1) add the column nullable with a `DEFAULT`, \
             backfill in a separate migration that batches updates, then \
             (2) flip to `NOT NULL` once backfill is verified. For Django, \
             use `RunPython` between the column add and the constraint \
             tighten."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 5,
    })
}
