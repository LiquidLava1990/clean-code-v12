//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe ships a positive (violating) case and a negative
//! (clean) case. Stubs ship a registration-only test. The pack-level
//! test confirms all seven rules register and resolve.

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::infinite_recursion::InfiniteRecursionRule;
use crate::missing_timeout::MissingTimeoutRule;
use crate::no_circuit_breaker::NoCircuitBreakerRule;
use crate::no_rate_limit::NoRateLimitRule;
use crate::retry_no_backoff::RetryNoBackoffRule;
use crate::unbounded_memory::UnboundedMemoryRule;
use crate::unbounded_queue::UnboundedQueueRule;
use crate::BuiltinOpsPack;

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

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_loop(batch: &mut CpgWriteBatch, parent: NodeId, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("while True".into()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

// ---------- missing_timeout ---------------------------------------------

#[test]
fn missing_timeout_flags_requests_get_without_timeout() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "requests.get",
        &[("args", Value::String("\"https://api.example.com\"".into()))],
        range(1, 1, 0, 30),
    );
    let findings = MissingTimeoutRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ops.missing_timeout");
}

#[test]
fn missing_timeout_silent_when_timeout_kwarg_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "requests.get",
        &[(
            "args",
            Value::String("\"https://api.example.com\", timeout=5".into()),
        )],
        range(1, 1, 0, 40),
    );
    assert!(MissingTimeoutRule.run(&fx.ctx()).is_empty());
}

// ---------- retry_no_backoff --------------------------------------------

#[test]
fn retry_no_backoff_flags_constant_sleep_in_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = push_loop(&mut fx.batch, file, range(1, 5, 0, 50));
    push_call_with_props(
        &mut fx.batch,
        loop_id,
        "time.sleep",
        &[("args", Value::String("1".into()))],
        range(2, 2, 5, 18),
    );
    let findings = RetryNoBackoffRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ops.retry_no_backoff");
}

#[test]
fn retry_no_backoff_silent_when_retry_library_used() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = push_loop(&mut fx.batch, file, range(1, 5, 0, 50));
    push_call_with_props(
        &mut fx.batch,
        loop_id,
        "time.sleep",
        &[("args", Value::String("1".into()))],
        range(2, 2, 5, 18),
    );
    push_simple_call(
        &mut fx.batch,
        loop_id,
        "tenacity.retry",
        range(3, 3, 19, 35),
    );
    assert!(RetryNoBackoffRule.run(&fx.ctx()).is_empty());
}

// ---------- no_circuit_breaker ------------------------------------------

#[test]
fn no_circuit_breaker_flags_external_client_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fn_id = push_function(&mut fx.batch, file, "fetch_users", range(1, 5, 0, 50));
    push_call_with_props(
        &mut fx.batch,
        fn_id,
        "requests.get",
        &[("args", Value::String("\"https://api.example.com\"".into()))],
        range(2, 2, 5, 30),
    );
    let findings = NoCircuitBreakerRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ops.no_circuit_breaker");
}

#[test]
fn no_circuit_breaker_silent_when_breaker_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fn_id = push_function(&mut fx.batch, file, "fetch_users", range(1, 5, 0, 50));
    push_simple_call(&mut fx.batch, fn_id, "requests.get", range(2, 2, 5, 30));
    push_simple_call(
        &mut fx.batch,
        fn_id,
        "CircuitBreaker.call",
        range(3, 3, 31, 60),
    );
    assert!(NoCircuitBreakerRule.run(&fx.ctx()).is_empty());
}

// ---------- unbounded_queue ---------------------------------------------

#[test]
fn unbounded_queue_flags_unbounded_constructor() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "queue.Queue(",
        &[("args", Value::String(String::new()))],
        range(1, 1, 0, 14),
    );
    let findings = UnboundedQueueRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ops.unbounded_queue");
}

#[test]
fn unbounded_queue_silent_when_maxsize_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call_with_props(
        &mut fx.batch,
        file,
        "queue.Queue(",
        &[("args", Value::String("maxsize=128".into()))],
        range(1, 1, 0, 25),
    );
    assert!(UnboundedQueueRule.run(&fx.ctx()).is_empty());
}

// ---------- unbounded_memory (stub) -------------------------------------

#[test]
fn unbounded_memory_stub_returns_empty() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_simple_call(&mut fx.batch, file, "anything", range(1, 1, 0, 8));
    assert!(UnboundedMemoryRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unbounded_memory_registered_with_canonical_id() {
    assert_eq!(UnboundedMemoryRule.rule_id(), "cc.ops.unbounded_memory");
}

// ---------- no_rate_limit -----------------------------------------------

#[test]
fn no_rate_limit_flags_external_function_without_limiter() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fn_id = push_function(&mut fx.batch, file, "scrape_pages", range(1, 5, 0, 50));
    push_simple_call(&mut fx.batch, fn_id, "requests.get", range(2, 2, 5, 30));
    let findings = NoRateLimitRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.ops.no_rate_limit");
}

#[test]
fn no_rate_limit_silent_when_governor_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fn_id = push_function(&mut fx.batch, file, "scrape_pages", range(1, 5, 0, 50));
    push_simple_call(&mut fx.batch, fn_id, "requests.get", range(2, 2, 5, 30));
    push_simple_call(
        &mut fx.batch,
        fn_id,
        "governor::RateLimiter::check",
        range(3, 3, 31, 60),
    );
    assert!(NoRateLimitRule.run(&fx.ctx()).is_empty());
}

// ---------- infinite_recursion (stub) -----------------------------------

#[test]
fn infinite_recursion_stub_returns_empty() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "recurse_forever", range(1, 5, 0, 50));
    assert!(InfiniteRecursionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn infinite_recursion_registered_with_canonical_id() {
    assert_eq!(InfiniteRecursionRule.rule_id(), "cc.ops.infinite_recursion");
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_seven_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinOpsPack)
        .expect("Family-12 pack registers without error");
    assert_eq!(reg.rules().count(), 7);
    for slug in [
        "cc.ops.missing_timeout",
        "cc.ops.retry_no_backoff",
        "cc.ops.no_circuit_breaker",
        "cc.ops.unbounded_queue",
        "cc.ops.unbounded_memory",
        "cc.ops.no_rate_limit",
        "cc.ops.infinite_recursion",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

#[test]
fn pack_id_is_stable() {
    assert_eq!(crate::PACK_ID, "cc-builtin-ops");
}
