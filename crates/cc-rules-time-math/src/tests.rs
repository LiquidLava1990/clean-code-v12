//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive (violating) and one negative
//! (clean) case. The pack-level test asserts all five rules register.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::dst_unsafe::DstUnsafeRule;
use crate::float_equality::FloatEqualityRule;
use crate::leap_second::LeapSecondRule;
use crate::money_in_float::MoneyInFloatRule;
use crate::naive_datetime::NaiveDatetimeRule;
use crate::BuiltinTimeMathPack;

// ---------- shared fixtures ------------------------------------------------

const SAMPLE_PATH: &str = "src/sample.py";

fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("python".into())),
    )
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

fn push_write(batch: &mut CpgWriteBatch, parent: NodeId, target: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String(target.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
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

// ---------- naive_datetime -------------------------------------------------

#[test]
fn naive_datetime_flags_datetime_now_without_tz() {
    let bytes = b"now = datetime.now()\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "datetime.now", range(1, 1, 6, 20));
    let findings = NaiveDatetimeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.math.naive_datetime");
}

#[test]
fn naive_datetime_silent_when_tz_keyword_present() {
    let bytes = b"now = datetime.now(tz=timezone.utc)\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "datetime.now", range(1, 1, 6, 35));
    assert!(NaiveDatetimeRule.run(&fx.ctx()).is_empty());
}

// ---------- float_equality -------------------------------------------------

#[test]
fn float_equality_flags_two_float_literals() {
    let bytes = b"if 0.1 + 0.2 == 0.3:\n    pass\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FloatEqualityRule.run(&fx.ctx());
    assert!(
        !findings.is_empty(),
        "expected float-eq finding; got {findings:?}"
    );
    assert_eq!(findings[0].rule_id, "cc.math.float_equality");
}

#[test]
fn float_equality_flags_ratio_identifier() {
    let bytes = b"if conversion_rate == target:\n    pass\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(!FloatEqualityRule.run(&fx.ctx()).is_empty());
}

#[test]
fn float_equality_silent_on_int_compare() {
    let bytes = b"if count == limit:\n    pass\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FloatEqualityRule.run(&fx.ctx()).is_empty());
}

// ---------- money_in_float -------------------------------------------------

#[test]
fn money_in_float_flags_amount_assigned_float_literal() {
    let bytes = b"total_amount = 99.99\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(&mut fx.batch, file, "total_amount", range(1, 1, 0, 20));
    let findings = MoneyInFloatRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.math.money_in_float");
}

#[test]
fn money_in_float_silent_on_integer_cents() {
    let bytes = b"amount_cents = 9999\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(&mut fx.batch, file, "amount_cents", range(1, 1, 0, 19));
    assert!(MoneyInFloatRule.run(&fx.ctx()).is_empty());
}

// ---------- dst_unsafe -----------------------------------------------------

#[test]
fn dst_unsafe_flags_timedelta_days_then_strftime() {
    let bytes =
        b"def f():\n    d = datetime.now() + timedelta(days=1)\n    return d.strftime('%Y')\n"
            .to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("f".into()))
            .with_prop("range", Value::Range(range(1, 3, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    push_call(&mut fx.batch, func, "timedelta", range(2, 2, 30, 45));
    push_call(&mut fx.batch, func, "strftime", range(3, 3, 50, 70));
    let findings = DstUnsafeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.math.dst_unsafe");
}

#[test]
fn dst_unsafe_silent_without_wall_clock_read() {
    let bytes =
        b"def f():\n    d = datetime.now(tz=timezone.utc) + timedelta(days=1)\n    return d\n"
            .to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("f".into()))
            .with_prop("range", Value::Range(range(1, 3, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    push_call(&mut fx.batch, func, "timedelta", range(2, 2, 50, 65));
    assert!(DstUnsafeRule.run(&fx.ctx()).is_empty());
}

// ---------- leap_second ----------------------------------------------------

#[test]
fn leap_second_flags_delta_div_86400() {
    // String split so this very test file does not self-trip the rule
    // when cc-cli scans the workspace as part of self-host smoke.
    let mut sample = String::from("days = (end - start)");
    sample.push_str(" / 864");
    sample.push_str("00\n");
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, sample.into_bytes());
    push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = LeapSecondRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.math.leap_second");
}

#[test]
fn leap_second_silent_on_unrelated_division() {
    let bytes = b"avg = total / count\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(LeapSecondRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ------------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTimeMathPack)
        .expect("Family-14 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.math.naive_datetime",
        "cc.math.float_equality",
        "cc.math.money_in_float",
        "cc.math.dst_unsafe",
        "cc.math.leap_second",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
