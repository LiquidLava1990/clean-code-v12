//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has a positive (violating) and a negative (clean)
//! case. Stub probes have a registration-only test. The pack-level
//! test confirms all five rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::cache_unbounded::CacheUnboundedRule;
use crate::double_free::DoubleFreeRule;
use crate::event_loop_leak::EventLoopLeakRule;
use crate::unclosed_resource::UnclosedResourceRule;
use crate::use_after_free::UseAfterFreeRule;
use crate::BuiltinMemoryPack;

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

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, is_async: bool) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("is_async", Value::Bool(is_async))
            .with_prop("range", Value::Range(range(1, 1, 0, 10))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_write(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    target: &str,
    initializer: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String(target.to_owned()))
            .with_prop("initializer", Value::String(initializer.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_method_call(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    receiver: &str,
    method: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("receiver", Value::String(receiver.to_owned()))
            .with_prop("method", Value::String(method.to_owned()))
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

// ---------- unclosed_resource -------------------------------------------

#[test]
fn unclosed_resource_flags_open_without_close() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "load", false);
    push_write(
        &mut fx.batch,
        fun,
        "fh",
        "open(\"x.txt\")",
        range(2, 2, 0, 18),
    );
    let findings = UnclosedResourceRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.memory.unclosed_resource");
}

#[test]
fn unclosed_resource_silent_when_close_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "load", false);
    push_write(
        &mut fx.batch,
        fun,
        "fh",
        "open(\"x.txt\")",
        range(2, 2, 0, 18),
    );
    push_method_call(&mut fx.batch, fun, "fh", "close", range(3, 3, 19, 28));
    assert!(UnclosedResourceRule.run(&fx.ctx()).is_empty());
}

// ---------- event_loop_leak ---------------------------------------------

#[test]
fn event_loop_leak_flags_uncancelled_create_task() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "boot", true);
    push_write(
        &mut fx.batch,
        fun,
        "task",
        "asyncio.create_task(work())",
        range(2, 2, 0, 30),
    );
    let findings = EventLoopLeakRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.memory.event_loop_leak");
}

#[test]
fn event_loop_leak_silent_when_handle_cancelled() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "boot", true);
    push_write(
        &mut fx.batch,
        fun,
        "task",
        "asyncio.create_task(work())",
        range(2, 2, 0, 30),
    );
    push_method_call(&mut fx.batch, fun, "task", "cancel", range(3, 3, 31, 41));
    assert!(EventLoopLeakRule.run(&fx.ctx()).is_empty());
}

// ---------- cache_unbounded ---------------------------------------------

#[test]
fn cache_unbounded_flags_module_scope_dict_with_inserts() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(&mut fx.batch, file, "_cache", "{}", range(1, 1, 0, 10));
    push_method_call(
        &mut fx.batch,
        file,
        "_cache",
        "__setitem__",
        range(2, 2, 11, 22),
    );
    let findings = CacheUnboundedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.memory.cache_unbounded");
}

#[test]
fn cache_unbounded_silent_when_eviction_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(&mut fx.batch, file, "_cache", "{}", range(1, 1, 0, 10));
    push_method_call(
        &mut fx.batch,
        file,
        "_cache",
        "__setitem__",
        range(2, 2, 11, 22),
    );
    push_method_call(&mut fx.batch, file, "_cache", "pop", range(3, 3, 23, 32));
    assert!(CacheUnboundedRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs (registration only) -----------------------------------

#[test]
fn use_after_free_stub_returns_no_findings() {
    let fx = Fixture::new();
    assert!(UseAfterFreeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn double_free_stub_returns_no_findings() {
    let fx = Fixture::new();
    assert!(DoubleFreeRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinMemoryPack)
        .expect("Family-6 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.memory.unclosed_resource",
        "cc.memory.use_after_free",
        "cc.memory.double_free",
        "cc.memory.event_loop_leak",
        "cc.memory.cache_unbounded",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
    let _ = SAMPLE_PATH; // silence unused-const warning if no test references it
    let _ = Utf8PathBuf::from("placeholder");
}
