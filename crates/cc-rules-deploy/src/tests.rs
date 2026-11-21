//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has at least one positive (violating) and one
//! negative (clean) case. Each stub has a registration-only test. The
//! pack-level test confirms all four rules register and resolve.

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::big_bang_migration::BigBangMigrationRule;
use crate::missing_feature_flag::MissingFeatureFlagRule;
use crate::no_rollback_path::NoRollbackPathRule;
use crate::stale_flag::StaleFlagRule;
use crate::BuiltinDeployPack;

// ---------- shared fixtures ----------------------------------------------

const SAMPLE_PATH: &str = "src/deploy.py";

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

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
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

// ---------- no_rollback_path --------------------------------------------

#[test]
fn no_rollback_flags_shutil_rmtree() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "shutil.rmtree", range(5, 5, 40, 60));
    let findings = NoRollbackPathRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.deploy.no_rollback_path");
}

#[test]
fn no_rollback_silent_on_safe_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "shutil.copy", range(5, 5, 40, 55));
    assert!(NoRollbackPathRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_rollback_skips_test_files() {
    let test_path = "tests/test_deploy.py";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, test_path);
    push_call(&mut fx.batch, file, "os.remove", range(5, 5, 40, 50));
    assert!(NoRollbackPathRule.run(&fx.ctx()).is_empty());
}

// ---------- big_bang_migration (stub) -----------------------------------

#[test]
fn big_bang_is_stub_silent() {
    let fx = Fixture::new();
    assert!(BigBangMigrationRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        BigBangMigrationRule.rule_id(),
        "cc.deploy.big_bang_migration"
    );
}

// ---------- missing_feature_flag ----------------------------------------

#[test]
fn missing_flag_flags_experimental_function_with_no_flag_check() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(
        &mut fx.batch,
        file,
        "experimental_rollout",
        range(1, 5, 0, 80),
    );
    // Body has a non-flag call.
    push_call(&mut fx.batch, func, "do_work", range(2, 2, 10, 20));
    let findings = MissingFeatureFlagRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.deploy.missing_feature_flag");
}

#[test]
fn missing_flag_silent_when_flag_evaluator_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "beta_pipeline", range(1, 5, 0, 80));
    push_call(&mut fx.batch, func, "feature_flag", range(2, 2, 10, 30));
    assert!(MissingFeatureFlagRule.run(&fx.ctx()).is_empty());
}

#[test]
fn missing_flag_silent_on_non_risky_name() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "process_order", range(1, 5, 0, 80));
    push_call(&mut fx.batch, func, "do_work", range(2, 2, 10, 20));
    assert!(MissingFeatureFlagRule.run(&fx.ctx()).is_empty());
}

// ---------- stale_flag (stub) -------------------------------------------

#[test]
fn stale_flag_is_stub_silent() {
    let fx = Fixture::new();
    assert!(StaleFlagRule.run(&fx.ctx()).is_empty());
    assert_eq!(StaleFlagRule.rule_id(), "cc.deploy.stale_flag");
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_four_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinDeployPack)
        .expect("Family-13 pack registers without error");
    assert_eq!(reg.rules().count(), 4);
    for slug in [
        "cc.deploy.no_rollback_path",
        "cc.deploy.big_bang_migration",
        "cc.deploy.missing_feature_flag",
        "cc.deploy.stale_flag",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

#[test]
fn pack_id_is_canonical() {
    assert_eq!(BuiltinDeployPack::PACK_ID, "cc-builtin-deploy");
    assert_eq!(crate::PACK_ID, "cc-builtin-deploy");
}
