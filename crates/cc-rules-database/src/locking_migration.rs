//! `cc.db.locking_migration` — migration that takes a long table-lock.
//!
//! Heuristic: walk every [`NodeKind::File`] whose path matches
//! `**/migrations/*.{sql,py}` (or the `*_migration.py` basename). Scan
//! the source bytes for `ALTER TABLE` followed by `ADD COLUMN` /
//! `ALTER COLUMN` / `RENAME COLUMN` / `DROP COLUMN` and verify the
//! statement also carries a non-locking marker:
//!
//! - Postgres: `CONCURRENTLY`
//! - MySQL: `INPLACE` / `LOCK=NONE`
//! - ORM-level: `online: true`
//!
//! Statements that mutate the schema without one of those markers
//! acquire `ACCESS EXCLUSIVE` / metadata locks for the duration of the
//! migration, blocking writers and (depending on engine) readers.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_migration_path, location_for_file, DatabaseFindingBlueprint,
};

/// Family-10 probe R-DB-LOCKING-MIGRATION.
#[derive(Debug, Default, Clone, Copy)]
pub struct LockingMigrationRule;

const COLUMN_VERBS: &[&str] = &["ADD COLUMN", "ALTER COLUMN", "RENAME COLUMN", "DROP COLUMN"];

const NON_LOCKING_MARKERS: &[&str] = &[
    "CONCURRENTLY",
    "INPLACE",
    "LOCK=NONE",
    "online: true",
    "online=True",
];

impl Rule for LockingMigrationRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.locking_migration"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE on a migration without CONCURRENTLY / INPLACE marker"
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
    let upper = text.to_ascii_uppercase();
    for (idx, line) in text.lines().enumerate() {
        if let Some(verb) = locking_verb_in_line(&upper, line) {
            let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(&path, line_no, line.trim(), verb));
        }
    }
}

/// Return the matched verb if the line is an unguarded column-altering
/// `ALTER TABLE` statement; `None` otherwise.
fn locking_verb_in_line(_upper_full: &str, line: &str) -> Option<&'static str> {
    let upper = line.to_ascii_uppercase();
    if !upper.contains("ALTER TABLE") {
        return None;
    }
    let verb = COLUMN_VERBS.iter().copied().find(|v| upper.contains(v))?;
    if NON_LOCKING_MARKERS
        .iter()
        .any(|m| upper.contains(&m.to_ascii_uppercase()))
    {
        return None;
    }
    Some(verb)
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str, verb: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(DatabaseFindingBlueprint {
        rule_id: "cc.db.locking_migration",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.75),
        location,
        headline: format!("`ALTER TABLE … {verb}` without a non-locking marker"),
        explanation: format!(
            "Migration `{}` runs `ALTER TABLE … {verb}` without `CONCURRENTLY` \
             (Postgres), `INPLACE` / `LOCK=NONE` (MySQL), or an `online: true` \
             ORM flag. The DDL takes a heavyweight table lock for the \
             duration of the rewrite — every reader and writer blocks. On \
             a busy table this produces a multi-minute outage.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Postgres: rewrite the statement with `CONCURRENTLY` (works for \
             index ops; for column ops, split into add-default-then-backfill). \
             MySQL: add `ALGORITHM=INPLACE, LOCK=NONE`. ORM: pass `online: \
             true` (Rails) / `atomic = False` + `RunSQL` (Django). For \
             impossible-online ops, schedule a maintenance window."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 5,
    })
}
