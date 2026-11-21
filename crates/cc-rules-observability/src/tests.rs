//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive (violating) and one negative
//! (clean) case. The pack-level test confirms all six rules register
//! and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::high_cardinality_label::HighCardinalityLabelRule;
use crate::missing_metrics::MissingMetricsRule;
use crate::no_correlation_id::NoCorrelationIdRule;
use crate::pii_in_log::PiiInLogRule;
use crate::silent_catch::SilentCatchRule;
use crate::unstructured_log::UnstructuredLogRule;
use crate::BuiltinObservabilityPack;

// ---------- shared fixtures ----------------------------------------------

const SAMPLE_PATH: &str = "src/sample.py";

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

fn push_call(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee_ref: &str,
    args: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("args", Value::String(args.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_function(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    visibility: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("visibility", Value::String(visibility.to_owned()))
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

// ---------- silent_catch -------------------------------------------------

#[test]
fn silent_catch_flags_logged_then_swallowed() {
    let body =
        b"try:\n    do()\nexcept Exception as e:\n    log.error(\"boom\")\n    return None\n";
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try).with_prop("range", Value::Range(range(1, 5, 0, len))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    let findings = SilentCatchRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.silent_catch");
}

#[test]
fn silent_catch_silent_when_reraised() {
    let body = b"try:\n    do()\nexcept Exception as e:\n    log.error(\"boom\")\n    raise\n";
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try).with_prop("range", Value::Range(range(1, 5, 0, len))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    assert!(SilentCatchRule.run(&fx.ctx()).is_empty());
}

// ---------- missing_metrics ---------------------------------------------

#[test]
fn missing_metrics_flags_public_io_without_metric() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(
        &mut fx.batch,
        file,
        "load_user",
        "public",
        range(1, 5, 0, 50),
    );
    push_call(
        &mut fx.batch,
        func,
        "requests.get",
        "url",
        range(2, 2, 10, 30),
    );
    let findings = MissingMetricsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.missing_metrics");
}

#[test]
fn missing_metrics_silent_when_metric_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(
        &mut fx.batch,
        file,
        "load_user",
        "public",
        range(1, 5, 0, 50),
    );
    push_call(
        &mut fx.batch,
        func,
        "requests.get",
        "url",
        range(2, 2, 10, 30),
    );
    push_call(
        &mut fx.batch,
        func,
        "metrics::counter",
        "\"requests\"",
        range(3, 3, 31, 50),
    );
    assert!(MissingMetricsRule.run(&fx.ctx()).is_empty());
}

// ---------- unstructured_log --------------------------------------------

#[test]
fn unstructured_log_flags_single_literal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(
        &mut fx.batch,
        file,
        "logger.info",
        "\"loaded user\"",
        range(1, 1, 0, 30),
    );
    let findings = UnstructuredLogRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.unstructured_log");
}

#[test]
fn unstructured_log_silent_with_kwargs() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(
        &mut fx.batch,
        file,
        "logger.info",
        "\"loaded\", extra={\"user_id\": uid}",
        range(1, 1, 0, 50),
    );
    assert!(UnstructuredLogRule.run(&fx.ctx()).is_empty());
}

// ---------- high_cardinality_label --------------------------------------

#[test]
fn high_cardinality_label_flags_user_id_label() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(
        &mut fx.batch,
        file,
        "metrics::counter",
        "\"requests\", \"user_id\" => uid",
        range(1, 1, 0, 50),
    );
    let findings = HighCardinalityLabelRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.high_cardinality_label");
}

#[test]
fn high_cardinality_label_silent_on_low_cardinality() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(
        &mut fx.batch,
        file,
        "metrics::counter",
        "\"requests\", \"status\" => \"ok\"",
        range(1, 1, 0, 50),
    );
    assert!(HighCardinalityLabelRule.run(&fx.ctx()).is_empty());
}

// ---------- no_correlation_id -------------------------------------------

#[test]
fn no_correlation_id_flags_http_without_tracing() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(
        &mut fx.batch,
        file,
        "fetch_thing",
        "public",
        range(1, 5, 0, 50),
    );
    push_call(
        &mut fx.batch,
        func,
        "requests.get",
        "url",
        range(2, 2, 10, 30),
    );
    let findings = NoCorrelationIdRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.no_correlation_id");
}

#[test]
fn no_correlation_id_silent_with_tracing_span() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(
        &mut fx.batch,
        file,
        "fetch_thing",
        "public",
        range(1, 5, 0, 50),
    );
    push_call(
        &mut fx.batch,
        func,
        "tracing::info_span",
        "\"fetch\"",
        range(2, 2, 10, 30),
    );
    push_call(
        &mut fx.batch,
        func,
        "requests.get",
        "url",
        range(3, 3, 31, 50),
    );
    assert!(NoCorrelationIdRule.run(&fx.ctx()).is_empty());
}

// ---------- pii_in_log --------------------------------------------------

#[test]
fn pii_in_log_flags_email_in_format() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String("logger.info".into()))
            .with_prop("format", Value::String("user signed up email=%s".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    let findings = PiiInLogRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.obs.pii_in_log");
}

#[test]
fn pii_in_log_silent_on_clean_format() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String("logger.info".into()))
            .with_prop("format", Value::String("user_id=%s signed up".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(PiiInLogRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_six_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinObservabilityPack)
        .expect("Family-11 pack registers without error");
    assert_eq!(reg.rules().count(), 6);
    for slug in [
        "cc.obs.silent_catch",
        "cc.obs.missing_metrics",
        "cc.obs.unstructured_log",
        "cc.obs.high_cardinality_label",
        "cc.obs.no_correlation_id",
        "cc.obs.pii_in_log",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
