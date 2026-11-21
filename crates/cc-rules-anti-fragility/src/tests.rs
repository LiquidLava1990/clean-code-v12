//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe ships a positive (violating) case, a negative
//! (clean) case, and a non-test-file-skip case. The stub probe ships a
//! registration test only. The pack-level test confirms all four rules
//! register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::network_in_test::NetworkInTestRule;
use crate::order_dependent::OrderDependentRule;
use crate::shared_global_state::SharedGlobalStateRule;
use crate::timing_assumption::TimingAssumptionRule;
use crate::BuiltinAntiFragilityPack;

// ---------- shared fixtures ----------------------------------------------

const TEST_PATH: &str = "tests/test_sample.py";
const PROD_PATH: &str = "src/sample.py";

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

fn push_call_with_props(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee_ref: &str,
    extra: &[(&str, Value)],
    rng: Range,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
        .with_prop("range", Value::Range(rng));
    for (key, value) in extra {
        builder = builder.with_prop(*key, value.clone());
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_simple_call(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee_ref: &str,
    rng: Range,
) -> NodeId {
    push_call_with_props(batch, parent, callee_ref, &[], rng)
}

fn push_write(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    target: &str,
    extra: &[(&str, Value)],
    rng: Range,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Write)
        .with_prop("target", Value::String(target.to_owned()))
        .with_prop("range", Value::Range(rng));
    for (key, value) in extra {
        builder = builder.with_prop(*key, value.clone());
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_module_var(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

// ---------- timing_assumption -------------------------------------------

#[test]
fn timing_assumption_flags_time_sleep_in_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_simple_call(&mut fx.batch, file, "time.sleep", range(1, 1, 0, 12));
    let findings = TimingAssumptionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.fragile.timing_assumption");
}

#[test]
fn timing_assumption_silent_on_non_sleep_call_in_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_simple_call(&mut fx.batch, file, "log.info", range(1, 1, 0, 8));
    assert!(TimingAssumptionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn timing_assumption_silent_on_sleep_in_production() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, PROD_PATH);
    push_simple_call(&mut fx.batch, file, "time.sleep", range(1, 1, 0, 12));
    assert!(TimingAssumptionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn timing_assumption_silent_on_sleep_in_rule_pack_source() {
    // Rule-pack tests embed sleep callee names as fixture data. The
    // path looks like `crates/cc-rules-perf/src/tests.rs` — a test
    // file by name AND a rule-pack source file. Skip to avoid
    // rule-on-rule self-flagging.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "crates/cc-rules-perf/src/tests.rs");
    push_simple_call(&mut fx.batch, file, "time.sleep", range(1, 1, 0, 12));
    assert!(
        TimingAssumptionRule.run(&fx.ctx()).is_empty(),
        "rule-pack source must not self-flag"
    );
}

// ---------- network_in_test ---------------------------------------------

#[test]
fn network_in_test_flags_external_url_in_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "requests.get",
        &[("arg0", Value::String("https://api.github.com/repos".into()))],
        range(1, 1, 0, 30),
    );
    let findings = NetworkInTestRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.fragile.network_in_test");
}

#[test]
fn network_in_test_silent_on_localhost_url() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "requests.get",
        &[("arg0", Value::String("http://127.0.0.1:8080/health".into()))],
        range(1, 1, 0, 30),
    );
    assert!(NetworkInTestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn network_in_test_silent_on_external_url_in_production() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, PROD_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "requests.get",
        &[("arg0", Value::String("https://api.github.com/repos".into()))],
        range(1, 1, 0, 30),
    );
    assert!(NetworkInTestRule.run(&fx.ctx()).is_empty());
}

// ---------- order_dependent (stub) --------------------------------------

#[test]
fn order_dependent_stub_returns_empty() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_simple_call(&mut fx.batch, file, "test_a", range(1, 1, 0, 6));
    assert!(OrderDependentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn order_dependent_registered_with_canonical_id() {
    assert_eq!(OrderDependentRule.rule_id(), "cc.fragile.order_dependent");
}

// ---------- shared_global_state -----------------------------------------

#[test]
fn shared_global_state_flags_module_var_write_in_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_module_var(&mut fx.batch, file, "COUNTER", range(1, 1, 0, 7));
    push_write(
        &mut fx.batch,
        file,
        "COUNTER",
        &[("initializer", Value::String("COUNTER + 1".into()))],
        range(2, 2, 8, 25),
    );
    let findings = SharedGlobalStateRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.fragile.shared_global_state");
}

#[test]
fn shared_global_state_silent_on_local_write_in_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_write(
        &mut fx.batch,
        file,
        "local_var",
        &[("initializer", Value::String("42".into()))],
        range(1, 1, 0, 12),
    );
    assert!(SharedGlobalStateRule.run(&fx.ctx()).is_empty());
}

#[test]
fn shared_global_state_silent_on_module_write_in_production() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, PROD_PATH);
    push_module_var(&mut fx.batch, file, "COUNTER", range(1, 1, 0, 7));
    push_write(
        &mut fx.batch,
        file,
        "COUNTER",
        &[("initializer", Value::String("COUNTER + 1".into()))],
        range(2, 2, 8, 25),
    );
    assert!(SharedGlobalStateRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_four_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinAntiFragilityPack)
        .expect("Family-23 pack registers without error");
    assert_eq!(reg.rules().count(), 4);
    for slug in [
        "cc.fragile.timing_assumption",
        "cc.fragile.network_in_test",
        "cc.fragile.order_dependent",
        "cc.fragile.shared_global_state",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

#[test]
fn pack_id_is_stable() {
    assert_eq!(crate::PACK_ID, "cc-builtin-anti-fragility");
}

// Suppress unused-import warning when only some helpers are used.
#[allow(dead_code)]
fn _touch_path_helper() -> Utf8PathBuf {
    Utf8PathBuf::from(TEST_PATH)
}
