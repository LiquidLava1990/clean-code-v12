//! Per-rule unit tests + a pack-registration integration test.

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::bus_factor::BusFactorRule;
use crate::churn_complexity_hotspot::ChurnComplexityHotspotRule;
use crate::parameter_creep::ParameterCreepRule;
use crate::partial_rewrites::PartialRewritesRule;
use crate::todo_aging::TodoAgingRule;
use crate::BuiltinHistoryPack;

const SAMPLE_PATH: &str = "src/lib.rs";

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
            .with_prop("language", Value::String("rust".into())),
    )
}

fn push_comment(batch: &mut CpgWriteBatch, parent: NodeId, text: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Comment)
            .with_prop("text", Value::String(text.to_owned()))
            .with_prop("kind", Value::String("line".into()))
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

// ---------- stubs -------------------------------------------------------

#[test]
fn churn_complexity_hotspot_is_stub_silent() {
    let fx = Fixture::new();
    assert!(ChurnComplexityHotspotRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        ChurnComplexityHotspotRule.rule_id(),
        "cc.rot.churn_complexity_hotspot"
    );
}

#[test]
fn parameter_creep_is_stub_silent() {
    let fx = Fixture::new();
    assert!(ParameterCreepRule.run(&fx.ctx()).is_empty());
    assert_eq!(ParameterCreepRule.rule_id(), "cc.rot.parameter_creep");
}

#[test]
fn partial_rewrites_is_stub_silent() {
    let fx = Fixture::new();
    assert!(PartialRewritesRule.run(&fx.ctx()).is_empty());
    assert_eq!(PartialRewritesRule.rule_id(), "cc.rot.partial_rewrites");
}

#[test]
fn bus_factor_is_stub_silent() {
    let fx = Fixture::new();
    assert!(BusFactorRule.run(&fx.ctx()).is_empty());
    assert_eq!(BusFactorRule.rule_id(), "cc.rot.bus_factor");
}

// ---------- todo_aging --------------------------------------------------

#[test]
fn todo_aging_flags_todo_comment() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_comment(
        &mut fx.batch,
        file,
        "// TODO: rewrite once async traits stabilise",
        range(1, 1, 0, 40),
    );
    let findings = TodoAgingRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.rot.todo_aging");
}

#[test]
fn todo_aging_silent_on_plain_comment() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_comment(
        &mut fx.batch,
        file,
        "// regular doc comment, no aging marker",
        range(1, 1, 0, 35),
    );
    assert!(TodoAgingRule.run(&fx.ctx()).is_empty());
}

#[test]
fn todo_aging_flags_fixme_xxx_hack() {
    for marker in ["FIXME", "XXX", "HACK"] {
        let mut fx = Fixture::new();
        let file = push_file(&mut fx.batch, SAMPLE_PATH);
        let text = format!("// {marker}: deferred work");
        push_comment(&mut fx.batch, file, &text, range(1, 1, 0, 30));
        let findings = TodoAgingRule.run(&fx.ctx());
        assert_eq!(findings.len(), 1, "marker {marker} should fire");
    }
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinHistoryPack)
        .expect("Family-18 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.rot.churn_complexity_hotspot",
        "cc.rot.parameter_creep",
        "cc.rot.partial_rewrites",
        "cc.rot.todo_aging",
        "cc.rot.bus_factor",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
