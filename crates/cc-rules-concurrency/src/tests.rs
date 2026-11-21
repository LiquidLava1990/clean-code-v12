//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive (violating) and one negative
//! (clean) case. The pack-level test confirms five rules registered.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::leaked_task::LeakedTaskRule;
use crate::lock_inversion::LockInversionRule;
use crate::race::RaceRule;
use crate::toctou::ToctouRule;
use crate::BuiltinConcurrencyPack;

// ---------- shared fixtures -----------------------------------------------

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

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, is_async: bool) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("is_async", Value::Bool(is_async))
            .with_prop("range", Value::Range(range(1, 10, 0, 80))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee: &str,
    arg: Option<&str>,
    rng: Range,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", Value::String(callee.to_owned()))
        .with_prop("range", Value::Range(rng));
    if let Some(a) = arg {
        builder = builder.with_prop("first_arg_value", Value::String(a.to_owned()));
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_write(batch: &mut CpgWriteBatch, parent: NodeId, target: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String(target.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_top_var(batch: &mut CpgWriteBatch, parent: NodeId, name: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range(1, 1, 0, 4))),
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

// ---------- race ----------------------------------------------------------

#[test]
fn race_flags_unguarded_async_write() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let _ = push_top_var(&mut fx.batch, file, "shared_state");
    let fun = push_function(&mut fx.batch, file, "tick", true);
    push_write(&mut fx.batch, fun, "shared_state", range(2, 2, 10, 30));
    let findings = RaceRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.race");
}

#[test]
fn race_silent_when_lock_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let _ = push_top_var(&mut fx.batch, file, "shared_state");
    let fun = push_function(&mut fx.batch, file, "tick", true);
    push_call(
        &mut fx.batch,
        fun,
        "self.lock.acquire",
        None,
        range(2, 2, 0, 18),
    );
    push_write(&mut fx.batch, fun, "shared_state", range(3, 3, 10, 30));
    assert!(RaceRule.run(&fx.ctx()).is_empty());
}

// ---------- lock_inversion -----------------------------------------------

#[test]
fn lock_inversion_flags_disagreeing_orders() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f1 = push_function(&mut fx.batch, file, "f1", false);
    push_call(&mut fx.batch, f1, "a.lock()", None, range(2, 2, 0, 8));
    push_call(&mut fx.batch, f1, "b.lock()", None, range(3, 3, 0, 8));
    let f2 = push_function(&mut fx.batch, file, "f2", false);
    push_call(&mut fx.batch, f2, "b.lock()", None, range(20, 20, 0, 8));
    push_call(&mut fx.batch, f2, "a.lock()", None, range(21, 21, 0, 8));
    let findings = LockInversionRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "expected at least one finding");
    assert!(findings
        .iter()
        .all(|f| f.rule_id == "cc.concurrent.lock_inversion"));
}

#[test]
fn lock_inversion_silent_when_orders_agree() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f1 = push_function(&mut fx.batch, file, "f1", false);
    push_call(&mut fx.batch, f1, "a.lock()", None, range(2, 2, 0, 8));
    push_call(&mut fx.batch, f1, "b.lock()", None, range(3, 3, 0, 8));
    let f2 = push_function(&mut fx.batch, file, "f2", false);
    push_call(&mut fx.batch, f2, "a.lock()", None, range(20, 20, 0, 8));
    push_call(&mut fx.batch, f2, "b.lock()", None, range(21, 21, 0, 8));
    assert!(LockInversionRule.run(&fx.ctx()).is_empty());
}

// ---------- leaked_task ---------------------------------------------------

#[test]
fn leaked_task_flags_unbound_create_task() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "kickoff", false);
    push_call(
        &mut fx.batch,
        fun,
        "asyncio.create_task",
        None,
        range(2, 2, 0, 25),
    );
    let findings = LeakedTaskRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.leaked_task");
}

#[test]
fn leaked_task_silent_when_assigned() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "kickoff", false);
    let write = push_write(&mut fx.batch, fun, "task", range(2, 2, 0, 30));
    push_call(
        &mut fx.batch,
        write,
        "asyncio.create_task",
        None,
        range(2, 2, 7, 30),
    );
    assert!(LeakedTaskRule.run(&fx.ctx()).is_empty());
}

#[test]
fn leaked_task_silent_in_rule_pack_source() {
    // Rule packs embed spawn-callee names like `setTimeout` / `tokio::spawn`
    // inside their remediation messages and string-literal fixtures. Substring
    // matching the source flags the detector for owning the shape it scans
    // for. Skip rule-pack source files until the AST detector lands.
    let mut fx = Fixture::new();
    let file = push_file(
        &mut fx.batch,
        "crates/cc-rules-anti-fragility/src/timing_assumption.rs",
    );
    let fun = push_function(&mut fx.batch, file, "explain", false);
    push_call(&mut fx.batch, fun, "setTimeout", None, range(2, 2, 0, 20));
    assert!(
        LeakedTaskRule.run(&fx.ctx()).is_empty(),
        "rule-pack source must not self-flag"
    );
}

// ---------- toctou --------------------------------------------------------

#[test]
fn toctou_flags_exists_then_open() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "load", false);
    push_call(
        &mut fx.batch,
        fun,
        "os.path.exists",
        Some("/etc/passwd"),
        range(2, 2, 100, 125),
    );
    push_call(
        &mut fx.batch,
        fun,
        "open",
        Some("/etc/passwd"),
        range(3, 3, 200, 218),
    );
    let findings = ToctouRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.toctou");
}

#[test]
fn toctou_silent_on_different_paths() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let fun = push_function(&mut fx.batch, file, "load", false);
    push_call(
        &mut fx.batch,
        fun,
        "os.path.exists",
        Some("/etc/passwd"),
        range(2, 2, 100, 125),
    );
    push_call(
        &mut fx.batch,
        fun,
        "open",
        Some("/tmp/scratch"),
        range(3, 3, 200, 220),
    );
    assert!(ToctouRule.run(&fx.ctx()).is_empty());
}

// ---------- waitgroup_add_in_goroutine (Phase 7) -------------------------

use crate::signal_unbuffered::SignalUnbufferedRule;
use crate::waitgroup_add_in_goroutine::WaitgroupAddInGoroutineRule;

fn fixture_with_go_source(path: &str, body: &str) -> Fixture {
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from(path), body.as_bytes().to_vec());
    let _file = push_file(&mut fx.batch, path);
    fx
}

#[test]
fn waitgroup_add_in_goroutine_flags_inner_add() {
    let body = "package main\n\
                func f() {\n\
                \tgo func() {\n\
                \t\twg.Add(1)\n\
                \t\tdefer wg.Done()\n\
                \t}()\n\
                }\n";
    let fx = fixture_with_go_source("src/main.go", body);
    let findings = WaitgroupAddInGoroutineRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.concurrent.waitgroup_add_in_goroutine"
    );
}

#[test]
fn waitgroup_add_in_goroutine_silent_when_add_outside() {
    let body = "package main\n\
                func f() {\n\
                \twg.Add(1)\n\
                \tgo func() {\n\
                \t\tdefer wg.Done()\n\
                \t}()\n\
                }\n";
    let fx = fixture_with_go_source("src/main.go", body);
    assert!(WaitgroupAddInGoroutineRule.run(&fx.ctx()).is_empty());
}

#[test]
fn waitgroup_add_in_goroutine_silent_in_test_files() {
    let body = "package main\n\
                func f() {\n\
                \tgo func() {\n\
                \t\twg.Add(1)\n\
                \t}()\n\
                }\n";
    let fx = fixture_with_go_source("src/main_test.go", body);
    assert!(WaitgroupAddInGoroutineRule.run(&fx.ctx()).is_empty());
}

// ---------- signal_unbuffered (Phase 7) ----------------------------------

#[test]
fn signal_unbuffered_flags_unbuffered_notify() {
    let body = "package main\n\
                import \"os/signal\"\n\
                func f() {\n\
                \tc := make(chan os.Signal)\n\
                \tsignal.Notify(c, os.Interrupt)\n\
                }\n";
    let fx = fixture_with_go_source("src/main.go", body);
    let findings = SignalUnbufferedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.signal_unbuffered");
}

#[test]
fn signal_unbuffered_silent_when_buffered() {
    let body = "package main\n\
                func f() {\n\
                \tc := make(chan os.Signal, 1)\n\
                \tsignal.Notify(c, os.Interrupt)\n\
                }\n";
    let fx = fixture_with_go_source("src/main.go", body);
    assert!(SignalUnbufferedRule.run(&fx.ctx()).is_empty());
}

#[test]
fn signal_unbuffered_silent_when_no_notify() {
    let body = "package main\n\
                func f() {\n\
                \tc := make(chan os.Signal)\n\
                \t_ = c\n\
                }\n";
    let fx = fixture_with_go_source("src/main.go", body);
    assert!(SignalUnbufferedRule.run(&fx.ctx()).is_empty());
}

// ---------- context_no_propagate (Phase 9 — Go) --------------------------

use crate::context_no_propagate::ContextNoPropagateRule;
use crate::copy_loop_var::CopyLoopVarRule;

#[test]
fn context_no_propagate_flags_background_inside_ctx_fn() {
    let body = "package svc\n\
                func handle(ctx context.Context, id string) error {\n    \
                    child := context.Background()\n    \
                    return doIt(child, id)\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = ContextNoPropagateRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.context_no_propagate");
}

#[test]
fn context_no_propagate_silent_when_ctx_passed() {
    let body = "package svc\n\
                func handle(ctx context.Context, id string) error {\n    \
                    return doIt(ctx, id)\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(ContextNoPropagateRule.run(&fx.ctx()).is_empty());
}

#[test]
fn context_no_propagate_silent_when_no_ctx_param() {
    // Functions without `context.Context` parameter are allowed to
    // create fresh root contexts — that's exactly when `Background()`
    // is the right call.
    let body = "package svc\n\
                func main() {\n    \
                    ctx := context.Background()\n    \
                    _ = ctx\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(ContextNoPropagateRule.run(&fx.ctx()).is_empty());
}

// ---------- copy_loop_var (Phase 9 — Go) ---------------------------------

#[test]
fn copy_loop_var_flags_capture_in_goroutine() {
    let body = "package svc\n\
                func run(items []int) {\n    \
                    for _, v := range items {\n        \
                        go func() {\n            \
                            use(v)\n        \
                        }()\n    \
                    }\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = CopyLoopVarRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.concurrent.copy_loop_var");
}

#[test]
fn copy_loop_var_silent_when_shadowed() {
    let body = "package svc\n\
                func run(items []int) {\n    \
                    for _, v := range items {\n        \
                        v := v\n        \
                        go func() {\n            \
                            use(v)\n        \
                        }()\n    \
                    }\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(CopyLoopVarRule.run(&fx.ctx()).is_empty());
}

#[test]
fn copy_loop_var_silent_in_test_files() {
    let body = "package svc\n\
                func run(items []int) {\n    \
                    for _, v := range items {\n        \
                        go func() { use(v) }()\n    \
                    }\n\
                }\n";
    let fx = fixture_with_go_source("src/svc_test.go", body);
    assert!(CopyLoopVarRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_eight_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinConcurrencyPack)
        .expect("Family-5 pack registers without error");
    assert_eq!(reg.rules().count(), 8);
    for slug in [
        "cc.concurrent.race",
        "cc.concurrent.lock_inversion",
        "cc.concurrent.leaked_task",
        "cc.concurrent.toctou",
        "cc.concurrent.waitgroup_add_in_goroutine",
        "cc.concurrent.signal_unbuffered",
        // Phase 9 (Go).
        "cc.concurrent.context_no_propagate",
        "cc.concurrent.copy_loop_var",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

// Use Utf8PathBuf so the rustc-incremental key is stable.
#[allow(dead_code)]
fn _phantom_path(p: &str) -> Utf8PathBuf {
    Utf8PathBuf::from(p)
}
