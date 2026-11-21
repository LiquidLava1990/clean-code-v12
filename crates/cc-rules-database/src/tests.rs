//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has at least one positive (violating) and one
//! negative (clean) case. Each stub has a registration-only test. The
//! pack-level test confirms all six rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::json_blob_hellscape::JsonBlobHellscapeRule;
use crate::locking_migration::LockingMigrationRule;
use crate::missing_backfill::MissingBackfillRule;
use crate::missing_fk::MissingFkRule;
use crate::missing_index::MissingIndexRule;
use crate::select_star_hot::SelectStarHotRule;
use crate::BuiltinDatabasePack;

// ---------- shared fixtures ----------------------------------------------

const SAMPLE_MODEL_PATH: &str = "src/models.py";
const SAMPLE_MIGRATION_PATH: &str = "src/migrations/0001_init.sql";
const SAMPLE_QUERY_PATH: &str = "src/queries.py";

const fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

const fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("python".into())),
    )
}

fn push_field(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    ty: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("type", Value::String(ty.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

struct Fixture {
    batch: CpgWriteBatch,
    source: InMemorySourceTable,
    config: RuleConfig,
    project: ProjectFingerprint,
    kernel: KernelMeta,
}

impl Fixture {
    fn new() -> Self {
        Self {
            batch: CpgWriteBatch::new(),
            source: InMemorySourceTable::new(),
            config: RuleConfig::default(),
            project: ProjectFingerprint::empty(),
            kernel: KernelMeta::now(),
        }
    }

    fn with_source(self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.source.insert(Utf8PathBuf::from(path), bytes);
        self
    }

    fn ctx(&self) -> RuleContext<'_> {
        RuleContext {
            batch: &self.batch,
            source: &self.source,
            config: &self.config,
            project: &self.project,
            kernel: &self.kernel,
        }
    }
}

// ---------- missing_index (stub) ----------------------------------------

#[test]
fn missing_index_is_stub_silent() {
    let fx = Fixture::new();
    assert!(MissingIndexRule.run(&fx.ctx()).is_empty());
    assert_eq!(MissingIndexRule.rule_id(), "cc.db.missing_index");
}

// ---------- missing_fk (stub) -------------------------------------------

#[test]
fn missing_fk_is_stub_silent() {
    let fx = Fixture::new();
    assert!(MissingFkRule.run(&fx.ctx()).is_empty());
    assert_eq!(MissingFkRule.rule_id(), "cc.db.missing_fk");
}

// ---------- json_blob_hellscape -----------------------------------------

#[test]
fn json_blob_flags_config_dict_jsonb() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_MODEL_PATH);
    push_field(
        &mut fx.batch,
        file,
        "config_dict",
        "Column(JSONB)",
        range(1, 1, 0, 30),
    );
    let findings = JsonBlobHellscapeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.db.json_blob_hellscape");
}

#[test]
fn json_blob_silent_on_relational_column() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_MODEL_PATH);
    push_field(
        &mut fx.batch,
        file,
        "user_id",
        "Column(Integer, ForeignKey('users.id'))",
        range(1, 1, 0, 40),
    );
    assert!(JsonBlobHellscapeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn json_blob_silent_on_unstructured_name() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_MODEL_PATH);
    // JSON-typed but field name is bare `payload` — not structured.
    push_field(
        &mut fx.batch,
        file,
        "payload",
        "Column(JSON)",
        range(1, 1, 0, 25),
    );
    assert!(JsonBlobHellscapeRule.run(&fx.ctx()).is_empty());
}

// ---------- locking_migration -------------------------------------------

#[test]
fn locking_migration_flags_alter_table_add_column() {
    let body = "ALTER TABLE users ADD COLUMN email TEXT;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_MIGRATION_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_MIGRATION_PATH);
    let findings = LockingMigrationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.db.locking_migration");
}

#[test]
fn locking_migration_silent_when_concurrently_present() {
    let body = "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);\n\
                ALTER TABLE users ADD COLUMN bio TEXT, ALGORITHM=INPLACE, LOCK=NONE;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_MIGRATION_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_MIGRATION_PATH);
    assert!(LockingMigrationRule.run(&fx.ctx()).is_empty());
}

#[test]
fn locking_migration_silent_outside_migrations_dir() {
    let body = "ALTER TABLE users ADD COLUMN email TEXT;\n";
    let mut fx = Fixture::new().with_source("src/raw.sql", body.as_bytes().to_vec());
    push_file(&mut fx.batch, "src/raw.sql");
    assert!(LockingMigrationRule.run(&fx.ctx()).is_empty());
}

// ---------- missing_backfill --------------------------------------------

#[test]
fn missing_backfill_flags_not_null_without_default() {
    let body = "ALTER TABLE users ADD COLUMN email TEXT NOT NULL;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_MIGRATION_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_MIGRATION_PATH);
    let findings = MissingBackfillRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.db.missing_backfill");
}

#[test]
fn missing_backfill_silent_when_default_present() {
    let body = "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';\n";
    let mut fx = Fixture::new().with_source(SAMPLE_MIGRATION_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_MIGRATION_PATH);
    assert!(MissingBackfillRule.run(&fx.ctx()).is_empty());
}

// ---------- select_star_hot ---------------------------------------------

#[test]
fn select_star_hot_flags_select_star_in_string() {
    let body = "rows = db.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))\n";
    let mut fx = Fixture::new().with_source(SAMPLE_QUERY_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_QUERY_PATH);
    let findings = SelectStarHotRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.db.select_star_hot");
}

#[test]
fn select_star_hot_silent_on_explicit_columns() {
    let body = "rows = db.execute(\"SELECT id, email FROM users\")\n";
    let mut fx = Fixture::new().with_source(SAMPLE_QUERY_PATH, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_QUERY_PATH);
    assert!(SelectStarHotRule.run(&fx.ctx()).is_empty());
}

#[test]
fn select_star_hot_skips_test_files() {
    let test_path = "tests/test_queries.py";
    let body = "rows = db.execute(\"SELECT * FROM users\")\n";
    let mut fx = Fixture::new().with_source(test_path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, test_path);
    assert!(SelectStarHotRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_six_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinDatabasePack)
        .expect("Family-10 pack registers without error");
    assert_eq!(reg.rules().count(), 6);
    for slug in [
        "cc.db.missing_index",
        "cc.db.missing_fk",
        "cc.db.json_blob_hellscape",
        "cc.db.locking_migration",
        "cc.db.missing_backfill",
        "cc.db.select_star_hot",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
