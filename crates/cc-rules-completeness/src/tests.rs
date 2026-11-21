//! Per-rule unit tests + a registry integration test.
//!
//! Each non-stub probe has at least one positive (violating) and one
//! negative (clean) case. Stub probes carry a registration check only —
//! the documented Phase-3 work is responsible for the behavioural tests.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::chain::consumer_no_emitter::ConsumerNoEmitterRule;
use crate::chain::event_no_consumer::EventNoConsumerRule;
use crate::chain::fn_no_event_emit::FnNoEventEmitRule;
use crate::chain::fn_no_typed_error::FnNoTypedErrorRule;
use crate::contract::errata_anchor_invalid::ErrataAnchorInvalidRule;
use crate::contract::event_unsigned::EventUnsignedRule;
use crate::contract::invariant_unmonitored::InvariantUnmonitoredRule;
use crate::contract::precondition_missing::PreconditionMissingRule;
use crate::decoration::circuit_breaker_missing::CircuitBreakerMissingRule;
use crate::decoration::rate_limit_missing::RateLimitMissingRule;
use crate::decoration::retry_no_backoff::RetryNoBackoffRule;
use crate::decoration::timeout_missing::TimeoutMissingRule;
use crate::error::bare_reraise::BareReraiseRule;
use crate::error::errcode_collision::ErrcodeCollisionRule;
use crate::error::no_errcode::NoErrcodeRule;
use crate::error::no_typed_class::NoTypedClassRule;
use crate::error::swallowed_with_log::SwallowedWithLogRule;
use crate::meta::duplicate_registration::DuplicateRegistrationRule;
use crate::meta::envelope_missing::EnvelopeMissingRule;
use crate::meta::fn_missing_decoration::FnMissingDecorationRule;
use crate::meta::io_schema_missing::IoSchemaMissingRule;
use crate::meta::side_effect_undeclared::SideEffectUndeclaredRule;
use crate::observe::missing_correlation_id::MissingCorrelationIdRule;
use crate::observe::public_fn_untraced::PublicFnUntracedRule;
use crate::observe::silent_io::SilentIoRule;
use crate::observe::span_name_drift::SpanNameDriftRule;
use crate::safety::public_fn_no_test::PublicFnNoTestRule;
use crate::safety::unsafe_block_no_safety_comment::UnsafeBlockNoSafetyCommentRule;
use crate::BuiltinCompletenessPack;

const SAMPLE_PATH: &str = "src/sample.rs";

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
            .with_prop("language", Value::String("rust".into())),
    )
}

fn push_function(
    batch: &mut CpgWriteBatch,
    parent_file: NodeId,
    name: &str,
    body_range: Range,
    is_pub: bool,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(body_range))
            .with_prop("is_pub", Value::Bool(is_pub)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent_file)
        .expect("edge endpoints exist");
    id
}

fn push_decorator(batch: &mut CpgWriteBatch, target: NodeId, name: &str, arg: Option<&str>) {
    let mut b = NodeBuilder::new(NodeKind::Decorator).with_prop("name", Value::String(name.into()));
    if let Some(a) = arg {
        b = b.with_prop("arg_name", Value::String(a.into()));
    }
    let id = batch.push_node(b);
    batch.push_edge(EdgeKind::AST_PARENT, id, target).unwrap();
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, range_v: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range_v)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_class(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, range_v: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String(name.into()))
            .with_prop("range", Value::Range(range_v)),
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

// ---------- observe::public_fn_untraced ----------------------------------

#[test]
fn public_fn_untraced_flags_naked_pub_fn() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "do_stuff", range(1, 1, 0, 1), true);
    let findings = PublicFnUntracedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.observe.public_fn_untraced");
}

#[test]
fn public_fn_untraced_silent_with_instrument() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "do_stuff", range(1, 1, 0, 1), true);
    push_decorator(&mut fx.batch, f, "tracing::instrument", None);
    assert!(PublicFnUntracedRule.run(&fx.ctx()).is_empty());
}

// ---------- observe::span_name_drift -------------------------------------

#[test]
fn span_name_drift_flags_mismatch() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "real_name", range(1, 1, 0, 1), true);
    push_decorator(&mut fx.batch, f, "instrument", Some("old_name"));
    let findings = SpanNameDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.observe.span_name_drift");
}

#[test]
fn span_name_drift_silent_when_aligned() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "do_stuff", range(1, 1, 0, 1), true);
    push_decorator(&mut fx.batch, f, "instrument", Some("do_stuff"));
    assert!(SpanNameDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- observe::missing_correlation_id ------------------------------

#[test]
fn missing_correlation_id_flags_handler_with_outbound() {
    let body = b"fn handle_request() { client.fetch(\"x\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "handle_request",
        range(1, 1, 0, total),
        true,
    );
    let findings = MissingCorrelationIdRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn missing_correlation_id_silent_with_traceparent() {
    let body = b"fn handle_request() { let h = traceparent(); client.fetch(\"x\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "handle_request",
        range(1, 1, 0, total),
        true,
    );
    assert!(MissingCorrelationIdRule.run(&fx.ctx()).is_empty());
}

// ---------- observe::silent_io -------------------------------------------

#[test]
fn silent_io_flags_untraced_io_call() {
    let body = b"fn do_disk() { fs::read(\"x\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "do_disk", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "fs::read", range(1, 1, 0, 10));
    let findings = SilentIoRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn silent_io_silent_with_instrument() {
    let body = b"fn do_disk() { fs::read(\"x\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "do_disk", range(1, 1, 0, total), false);
    push_decorator(&mut fx.batch, f, "tracing::instrument", None);
    push_call(&mut fx.batch, f, "fs::read", range(1, 1, 0, 10));
    assert!(SilentIoRule.run(&fx.ctx()).is_empty());
}

// ---------- meta::fn_missing_decoration ---------------------------------

#[test]
fn fn_missing_decoration_flags_naked_pub() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "do_x", range(1, 1, 0, 1), true);
    assert_eq!(FnMissingDecorationRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn fn_missing_decoration_silent_with_meta() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "do_x", range(1, 1, 0, 1), true);
    push_decorator(&mut fx.batch, f, "meta_async", None);
    assert!(FnMissingDecorationRule.run(&fx.ctx()).is_empty());
}

// ---------- meta::side_effect_undeclared --------------------------------

#[test]
fn side_effect_flags_io_without_decoration() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "save", range(1, 1, 0, 1), true);
    push_call(&mut fx.batch, f, "fs::write", range(1, 1, 0, 1));
    assert_eq!(SideEffectUndeclaredRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn side_effect_silent_with_decoration() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "save", range(1, 1, 0, 1), true);
    push_decorator(&mut fx.batch, f, "side_effect", None);
    push_call(&mut fx.batch, f, "fs::write", range(1, 1, 0, 1));
    assert!(SideEffectUndeclaredRule.run(&fx.ctx()).is_empty());
}

// ---------- meta::envelope_missing --------------------------------------

#[test]
fn envelope_missing_flags_anyhow() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("do_x".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("is_pub", Value::Bool(true))
            .with_prop("return_type", Value::String("anyhow::Result<()>".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert_eq!(EnvelopeMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn envelope_missing_silent_typed() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("do_x".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("is_pub", Value::Bool(true))
            .with_prop("return_type", Value::String("Result<u32, MyError>".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(EnvelopeMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- meta::io_schema_missing -------------------------------------

#[test]
fn io_schema_flags_serialize_without_schema() {
    let body = b"fn serialize_user() { return s; }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "serialize_user",
        range(1, 1, 0, total),
        false,
    );
    assert_eq!(IoSchemaMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn io_schema_silent_with_schema() {
    let body = b"fn serialize_user() { #[serde(rename=\"x\")] let s = 0; }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "serialize_user",
        range(1, 1, 0, total),
        false,
    );
    assert!(IoSchemaMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- meta::duplicate_registration --------------------------------

#[test]
fn duplicate_registration_flags_collision() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f1 = push_function(&mut fx.batch, file, "a", range(1, 1, 0, 1), true);
    let f2 = push_function(&mut fx.batch, file, "b", range(2, 2, 1, 2), true);
    push_decorator(&mut fx.batch, f1, "register_fn", Some("dup"));
    push_decorator(&mut fx.batch, f2, "register_fn", Some("dup"));
    let findings = DuplicateRegistrationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 2);
}

#[test]
fn duplicate_registration_silent_when_unique() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f1 = push_function(&mut fx.batch, file, "a", range(1, 1, 0, 1), true);
    let f2 = push_function(&mut fx.batch, file, "b", range(2, 2, 1, 2), true);
    push_decorator(&mut fx.batch, f1, "register_fn", Some("a"));
    push_decorator(&mut fx.batch, f2, "register_fn", Some("b"));
    assert!(DuplicateRegistrationRule.run(&fx.ctx()).is_empty());
}

// ---------- contract::precondition_missing -------------------------------

#[test]
fn precondition_missing_flags_unsafe() {
    let body = b"fn risky() { unsafe { *p = 0; } }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "risky", range(1, 1, 0, total), true);
    assert_eq!(PreconditionMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn precondition_missing_silent_with_assert() {
    let body = b"fn risky() { assert!(p.is_some()); unsafe { *p = 0; } }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "risky", range(1, 1, 0, total), true);
    assert!(PreconditionMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- contract::invariant_unmonitored ------------------------------

#[test]
fn invariant_unmonitored_flags_doc_only() {
    let body = b"// INVARIANT: x > 0\nfn f() { return; }";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert_eq!(InvariantUnmonitoredRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn invariant_unmonitored_silent_when_guarded() {
    let body = b"// INVARIANT: x > 0\nfn f(x: u32) { assert!(x > 0); }";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(InvariantUnmonitoredRule.run(&fx.ctx()).is_empty());
}

// ---------- contract::event_unsigned -------------------------------------

#[test]
fn event_unsigned_flags_emit_without_signature() {
    let body = b"fn f() { bus.emit(\"x\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "bus.emit", range(1, 1, 0, total));
    assert_eq!(EventUnsignedRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn event_unsigned_silent_when_signed() {
    let body = b"fn f() { bus.emit(payload.sign_with(key)); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "bus.emit", range(1, 1, 0, total));
    assert!(EventUnsignedRule.run(&fx.ctx()).is_empty());
}

// ---------- contract::errata_anchor_invalid ------------------------------

#[test]
fn errata_anchor_flags_positional() {
    let body = b"// errata: src/foo.py:123\nfn f() {}";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(!ErrataAnchorInvalidRule.run(&fx.ctx()).is_empty());
}

#[test]
fn errata_anchor_silent_without_pattern() {
    let body = b"// no anchor here\nfn f() {}";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(ErrataAnchorInvalidRule.run(&fx.ctx()).is_empty());
}

// ---------- error::no_typed_class ----------------------------------------

#[test]
fn no_typed_class_flags_generic_exception() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("raise".into()))
            .with_prop("exception_type", Value::String("Exception".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert_eq!(NoTypedClassRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn no_typed_class_silent_on_typed() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("raise".into()))
            .with_prop("exception_type", Value::String("ConfigError".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(NoTypedClassRule.run(&fx.ctx()).is_empty());
}

// ---------- error::no_errcode --------------------------------------------

#[test]
fn no_errcode_flags_class_without_code() {
    let body = b"class FooError: pass";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_class(&mut fx.batch, file, "FooError", range(1, 1, 0, total));
    assert_eq!(NoErrcodeRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn no_errcode_silent_when_present() {
    let body = b"class FooError: errcode = \"E1\"";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_class(&mut fx.batch, file, "FooError", range(1, 1, 0, total));
    assert!(NoErrcodeRule.run(&fx.ctx()).is_empty());
}

// ---------- error::errcode_collision -------------------------------------

#[test]
fn errcode_collision_flags_duplicates() {
    let body = b"class A: errcode = \"E1\"\nclass B: errcode = \"E1\"";
    let bytes = body.to_vec();
    let len_a = b"class A: errcode = \"E1\"".len() as u32;
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_class(&mut fx.batch, file, "AError", range(1, 1, 0, len_a));
    push_class(&mut fx.batch, file, "BError", range(2, 2, len_a, total));
    let findings = ErrcodeCollisionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 2);
}

#[test]
fn errcode_collision_silent_when_unique() {
    let body = b"class A: errcode = \"E1\"\nclass B: errcode = \"E2\"";
    let bytes = body.to_vec();
    let len_a = b"class A: errcode = \"E1\"".len() as u32;
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_class(&mut fx.batch, file, "AError", range(1, 1, 0, len_a));
    push_class(&mut fx.batch, file, "BError", range(2, 2, len_a, total));
    assert!(ErrcodeCollisionRule.run(&fx.ctx()).is_empty());
}

// ---------- error::bare_reraise ------------------------------------------

#[test]
fn bare_reraise_flags_python_pattern() {
    let body = b"try:\n    x()\nexcept Exception: raise\n";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(!BareReraiseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_reraise_silent_when_chained() {
    let body = b"try:\n    x()\nexcept Exception as e:\n    raise FooError() from e";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(BareReraiseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_reraise_skips_rule_pack_source() {
    // Probe source files embed the literal pattern strings as detector
    // needles / fixture bodies. Scanning them produces rule-on-rule
    // noise. Phase-2 conservative skip — see helpers TODO.
    let pack_path = "crates/cc-rules-completeness/src/error/bare_reraise.rs";
    let body = b"const NEEDLES: &[&str] = &[\"except Exception: raise\"];";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(pack_path, bytes);
    push_file(&mut fx.batch, pack_path);
    assert!(BareReraiseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_reraise_still_fires_on_application_python_source() {
    // Anchor: ensure the path-skip is narrow — application code under
    // a non-pack path still produces the finding.
    let app_path = "src/app/handlers.py";
    let body = b"try:\n    x()\nexcept Exception: raise\n";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(app_path, bytes);
    push_file(&mut fx.batch, app_path);
    assert!(!BareReraiseRule.run(&fx.ctx()).is_empty());
}

// ---------- error::swallowed_with_log ------------------------------------

#[test]
fn swallowed_with_log_flags_log_only() {
    let body = b"try {\n    foo();\n} catch (e) {\n    console.log(e);\n}";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(!SwallowedWithLogRule.run(&fx.ctx()).is_empty());
}

#[test]
fn swallowed_with_log_silent_when_rethrown() {
    let body = b"try {\n    foo();\n} catch (e) {\n    console.log(e);\n    throw e;\n}";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(SwallowedWithLogRule.run(&fx.ctx()).is_empty());
}

// ---------- decoration::timeout_missing ----------------------------------

#[test]
fn timeout_missing_flags_naked_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, 1), false);
    let cid = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("http.get".into()))
            .with_prop("args", Value::String("(\"x\")".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, cid, f).unwrap();
    assert_eq!(TimeoutMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn timeout_missing_silent_with_timeout() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, 1), false);
    let cid = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("http.get".into()))
            .with_prop("args", Value::String("(\"x\", timeout=5)".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, cid, f).unwrap();
    assert!(TimeoutMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- decoration::retry_no_backoff ---------------------------------

#[test]
fn retry_no_backoff_flags_constant_sleep() {
    let body = b"fn r() { for retry in 0..3 { sleep(1); } }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "r", range(1, 1, 0, total), true);
    assert_eq!(RetryNoBackoffRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn retry_no_backoff_silent_with_jitter() {
    let body = b"fn r() { for retry in 0..3 { backoff::with_jitter(); } }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "r", range(1, 1, 0, total), true);
    assert!(RetryNoBackoffRule.run(&fx.ctx()).is_empty());
}

// ---------- decoration::circuit_breaker_missing --------------------------

#[test]
fn circuit_breaker_missing_flags_external_call() {
    let body = b"fn f() { redis.get(\"k\"); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "redis.get", range(1, 1, 0, total));
    assert_eq!(CircuitBreakerMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn circuit_breaker_missing_silent_when_wrapped() {
    let body = b"fn f() { circuit::run(|| redis.get(\"k\")); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "redis.get", range(1, 1, 0, total));
    assert!(CircuitBreakerMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- decoration::rate_limit_missing -------------------------------

#[test]
fn rate_limit_missing_flags_external_call() {
    let body = b"fn f() { stripe.charge(c); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "stripe.charge", range(1, 1, 0, total));
    assert_eq!(RateLimitMissingRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn rate_limit_missing_silent_with_throttle() {
    let body = b"fn f() { throttle(stripe.charge, c); }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), false);
    push_call(&mut fx.batch, f, "stripe.charge", range(1, 1, 0, total));
    assert!(RateLimitMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- chain::fn_no_typed_error -------------------------------------

#[test]
fn fn_no_typed_error_flags_anyhow() {
    let body = b"fn f() { Err(anyhow!(\"x\")) }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), true);
    assert_eq!(FnNoTypedErrorRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn fn_no_typed_error_silent_when_typed() {
    let body = b"fn f() { Err(MyError::Bad) }";
    let bytes = body.to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "f", range(1, 1, 0, total), true);
    assert!(FnNoTypedErrorRule.run(&fx.ctx()).is_empty());
}

// ---------- chain::fn_no_event_emit --------------------------------------

#[test]
fn fn_no_event_emit_flags_save_without_emit() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "save_user", range(1, 1, 0, 1), true);
    assert_eq!(FnNoEventEmitRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn fn_no_event_emit_silent_with_emit() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "save_user", range(1, 1, 0, 1), true);
    push_call(&mut fx.batch, f, "bus.emit", range(1, 1, 0, 1));
    assert!(FnNoEventEmitRule.run(&fx.ctx()).is_empty());
}

// ---------- chain::event_no_consumer / consumer_no_emitter ---------------

#[test]
fn event_no_consumer_flags_orphan_emit() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, 1), false);
    let cid = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("bus.emit".into()))
            .with_prop("event_name", Value::String("UserSaved".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, cid, f).unwrap();
    assert_eq!(EventNoConsumerRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn event_no_consumer_silent_when_paired() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, 1), false);
    let emit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("bus.emit".into()))
            .with_prop("event_name", Value::String("UserSaved".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    let sub = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("on_event".into()))
            .with_prop("event_name", Value::String("UserSaved".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, emit, f).unwrap();
    fx.batch.push_edge(EdgeKind::AST_PARENT, sub, f).unwrap();
    assert!(EventNoConsumerRule.run(&fx.ctx()).is_empty());
    assert!(ConsumerNoEmitterRule.run(&fx.ctx()).is_empty());
}

#[test]
fn consumer_no_emitter_flags_orphan_subscriber() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "f", range(1, 1, 0, 1), false);
    let sub = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("on_event".into()))
            .with_prop("event_name", Value::String("UserSaved".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, sub, f).unwrap();
    assert_eq!(ConsumerNoEmitterRule.run(&fx.ctx()).len(), 1);
}

// ---------- safety::public_fn_no_test (Phase 10) ------------------------

#[test]
fn public_fn_no_test_flags_pub_fn_with_no_matching_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/svc.rs");
    push_function(
        &mut fx.batch,
        file,
        "compute_total",
        range(1, 1, 0, 1),
        true,
    );
    let findings = PublicFnNoTestRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.complete.public_fn_no_test");
}

#[test]
fn public_fn_no_test_silent_when_test_names_function() {
    let mut fx = Fixture::new();
    let src_file = push_file(&mut fx.batch, "src/svc.rs");
    push_function(
        &mut fx.batch,
        src_file,
        "compute_total",
        range(1, 1, 0, 1),
        true,
    );
    let test_file = push_file(&mut fx.batch, "src/tests/svc_test.rs");
    push_function(
        &mut fx.batch,
        test_file,
        "test_compute_total_basic",
        range(1, 1, 0, 1),
        false,
    );
    assert!(PublicFnNoTestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn public_fn_no_test_silent_for_private_fn() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/svc.rs");
    push_function(
        &mut fx.batch,
        file,
        "compute_total",
        range(1, 1, 0, 1),
        false,
    );
    assert!(PublicFnNoTestRule.run(&fx.ctx()).is_empty());
}

// ---------- safety::unsafe_block_no_safety_comment (Phase 10) ----------

#[test]
fn unsafe_block_no_safety_comment_flags_undocumented_block() {
    let body = b"fn use_raw(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source("src/raw.rs", bytes);
    push_file(&mut fx.batch, "src/raw.rs");
    let findings = UnsafeBlockNoSafetyCommentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.complete.unsafe_block_no_safety_comment"
    );
}

#[test]
fn unsafe_block_no_safety_comment_silent_with_safety_comment() {
    let body = b"fn use_raw(p: *const u8) -> u8 {\n    // SAFETY: caller guarantees p is non-null and aligned\n    unsafe { *p }\n}\n";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source("src/raw.rs", bytes);
    push_file(&mut fx.batch, "src/raw.rs");
    assert!(UnsafeBlockNoSafetyCommentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unsafe_block_no_safety_comment_silent_for_unsafe_fn_declaration() {
    // `unsafe fn foo()` is a declaration, not a block — must not flag.
    let body = b"unsafe fn use_raw(p: *const u8) -> u8 { *p }\n";
    let bytes = body.to_vec();
    let mut fx = Fixture::new().with_source("src/raw.rs", bytes);
    push_file(&mut fx.batch, "src/raw.rs");
    assert!(UnsafeBlockNoSafetyCommentRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_30_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinCompletenessPack)
        .expect("Family-25 pack registers without error");
    assert_eq!(reg.rules().count(), 30);
    for slug in [
        "cc.observe.public_fn_untraced",
        "cc.observe.span_name_drift",
        "cc.observe.missing_correlation_id",
        "cc.observe.silent_io",
        "cc.meta.fn_missing_decoration",
        "cc.meta.side_effect_undeclared",
        "cc.meta.envelope_missing",
        "cc.meta.io_schema_missing",
        "cc.meta.duplicate_registration",
        "cc.contract.precondition_missing",
        "cc.contract.postcondition_missing",
        "cc.contract.invariant_unmonitored",
        "cc.contract.event_unsigned",
        "cc.contract.errata_anchor_invalid",
        "cc.error.no_typed_class",
        "cc.error.no_errcode",
        "cc.error.errcode_collision",
        "cc.error.bare_reraise",
        "cc.error.swallowed_with_log",
        "cc.decoration.timeout_missing",
        "cc.decoration.retry_no_backoff",
        "cc.decoration.circuit_breaker_missing",
        "cc.decoration.rate_limit_missing",
        "cc.chain.fn_in_pathway_no_registry",
        "cc.chain.fn_no_typed_error",
        "cc.chain.fn_no_event_emit",
        "cc.chain.event_no_consumer",
        "cc.chain.consumer_no_emitter",
        "cc.complete.public_fn_no_test",
        "cc.complete.unsafe_block_no_safety_comment",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
