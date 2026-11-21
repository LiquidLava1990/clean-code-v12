//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has at least one positive (violating) and one
//! negative (clean) case. Each stub has a registration-only test. The
//! pack-level test confirms all five rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::flaky_test_history::FlakyTestHistoryRule;
use crate::hook_bypass_in_history::HookBypassInHistoryRule;
use crate::lockfile_uncommitted::LockfileUncommittedRule;
use crate::missing_step::MissingStepRule;
use crate::slow_test::SlowTestRule;
use crate::BuiltinCiPack;

// ---------- shared fixtures ----------------------------------------------

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("yaml".into())),
    )
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

// ---------- flaky_test_history (stub) -----------------------------------

#[test]
fn flaky_test_history_is_stub_silent() {
    let fx = Fixture::new();
    assert!(FlakyTestHistoryRule.run(&fx.ctx()).is_empty());
    assert_eq!(FlakyTestHistoryRule.rule_id(), "cc.ci.flaky_test_history");
}

// ---------- slow_test (stub) --------------------------------------------

#[test]
fn slow_test_is_stub_silent() {
    let fx = Fixture::new();
    assert!(SlowTestRule.run(&fx.ctx()).is_empty());
    assert_eq!(SlowTestRule.rule_id(), "cc.ci.slow_test");
}

// ---------- hook_bypass_in_history (stub) -------------------------------

#[test]
fn hook_bypass_in_history_is_stub_silent() {
    let fx = Fixture::new();
    assert!(HookBypassInHistoryRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        HookBypassInHistoryRule.rule_id(),
        "cc.ci.hook_bypass_in_history"
    );
}

// ---------- missing_step ------------------------------------------------

#[test]
fn missing_step_flags_workflow_without_test_keywords() {
    let path = ".github/workflows/deploy.yml";
    let body = "name: deploy\n\
                on: push\n\
                jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n\
                      - run: echo hello\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = MissingStepRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ci.missing_step");
}

#[test]
fn missing_step_silent_when_test_keyword_present() {
    let path = ".github/workflows/ci.yml";
    let body = "jobs:\n  test:\n    steps:\n      - run: cargo test\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(MissingStepRule.run(&fx.ctx()).is_empty());
}

// ---------- lockfile_uncommitted ----------------------------------------

#[test]
fn lockfile_uncommitted_flags_orphan_cargo_toml() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    let findings = LockfileUncommittedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ci.lockfile_uncommitted");
}

#[test]
fn lockfile_uncommitted_silent_when_lock_present() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    push_file(&mut fx.batch, "Cargo.lock");
    assert!(LockfileUncommittedRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinCiPack)
        .expect("Family-17 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.ci.flaky_test_history",
        "cc.ci.slow_test",
        "cc.ci.missing_step",
        "cc.ci.lockfile_uncommitted",
        "cc.ci.hook_bypass_in_history",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
