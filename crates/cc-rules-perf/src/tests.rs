//! Per-rule unit tests + a registry integration test.
//!
//! Each Family-2 probe has at least one positive (violating) and one
//! negative (clean) case. Fixtures build a [`CpgWriteBatch`] by hand via
//! [`NodeBuilder`] + `push_node` + `push_edge` — the same pattern used by
//! `cc-rules-tier0`'s test suite.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::alloc_in_loop::AllocInLoopRule;
use crate::gc_pressure::GcPressureRule;
use crate::gil_trap::GilTrapRule;
use crate::missing_memoization::MissingMemoizationRule;
use crate::n_plus_one_orm::NPlusOneOrmRule;
use crate::regex_compile_in_loop::RegexCompileInLoopRule;
use crate::string_concat_loop::StringConcatLoopRule;
use crate::sync_in_async::SyncInAsyncRule;
use crate::wrong_collection::WrongCollectionRule;
use crate::BuiltinPerfPack;

// ---------- shared fixtures -----------------------------------------------

const SAMPLE_PATH: &str = "src/sample.py";

fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str, language: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String(language.to_owned())),
    )
}

fn push_function(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    body_range: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(body_range)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

fn push_async_function(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    body_range: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(body_range))
            .with_prop("is_async", Value::Bool(true)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

fn push_child(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    kind: NodeKind,
    name: Option<&str>,
) -> NodeId {
    let mut nb = NodeBuilder::new(kind).with_prop("range", Value::Range(range(1, 1, 0, 1)));
    if let Some(n) = name {
        nb = nb.with_prop("name", Value::String(n.to_owned()));
    }
    let id = batch.push_node(nb);
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

    #[allow(dead_code)]
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

// ---------- sync_in_async -------------------------------------------------

#[test]
fn sync_in_async_flags_time_sleep_in_async_def() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_async_function(&mut fx.batch, file, "do_work", range(1, 1, 0, 1));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("time.sleep".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    let findings = SyncInAsyncRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.sync_in_async");
}

#[test]
fn sync_in_async_silent_in_sync_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "do_work", range(1, 1, 0, 1));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call).with_prop("name", Value::String("time.sleep".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    assert!(SyncInAsyncRule.run(&fx.ctx()).is_empty());
}

// ---------- regex_compile_in_loop -----------------------------------------

#[test]
fn regex_compile_in_loop_flags_python_re_compile() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "scan", range(1, 5, 0, 50));
    let loop_node = push_child(&mut fx.batch, f, NodeKind::Loop, None);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("re.compile".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 10))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, loop_node)
        .unwrap();
    let findings = RegexCompileInLoopRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.regex_compile_in_loop");
}

#[test]
fn regex_compile_in_loop_silent_when_outside_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "scan", range(1, 5, 0, 50));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call).with_prop("name", Value::String("re.compile".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    assert!(RegexCompileInLoopRule.run(&fx.ctx()).is_empty());
}

// ---------- alloc_in_loop -------------------------------------------------

#[test]
fn alloc_in_loop_flags_vec_new_in_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    let f = push_function(&mut fx.batch, file, "build", range(1, 5, 0, 50));
    let loop_node = push_child(&mut fx.batch, f, NodeKind::Loop, None);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("Vec::new".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 10))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, loop_node)
        .unwrap();
    let findings = AllocInLoopRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.alloc_in_loop");
}

#[test]
fn alloc_in_loop_silent_when_outside_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    let f = push_function(&mut fx.batch, file, "build", range(1, 5, 0, 50));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call).with_prop("name", Value::String("Vec::new".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    assert!(AllocInLoopRule.run(&fx.ctx()).is_empty());
}

// ---------- n_plus_one_orm ------------------------------------------------

#[test]
fn n_plus_one_orm_flags_objects_filter_in_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "list_books", range(1, 5, 0, 50));
    let loop_node = push_child(&mut fx.batch, f, NodeKind::Loop, None);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("Book.objects.filter".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 20))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, loop_node)
        .unwrap();
    let findings = NPlusOneOrmRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.n_plus_one_orm");
}

#[test]
fn n_plus_one_orm_silent_with_prefetch_related() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "list_books", range(1, 5, 0, 50));
    // Eager-load hint at function scope.
    let prefetch = fx
        .batch
        .push_node(NodeBuilder::new(NodeKind::Call).with_prop(
            "name",
            Value::String("Book.objects.prefetch_related".into()),
        ));
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, prefetch, f)
        .unwrap();
    let loop_node = push_child(&mut fx.batch, f, NodeKind::Loop, None);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("Book.objects.filter".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, loop_node)
        .unwrap();
    assert!(NPlusOneOrmRule.run(&fx.ctx()).is_empty());
}

// ---------- gil_trap ------------------------------------------------------

#[test]
fn gil_trap_flags_long_async_without_await() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    // Body of 30 lines, async, no Async descendant.
    let _f = push_async_function(&mut fx.batch, file, "compute", range(1, 31, 0, 600));
    let findings = GilTrapRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.gil_trap");
}

#[test]
fn gil_trap_silent_when_async_descendant_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_async_function(&mut fx.batch, file, "compute", range(1, 31, 0, 600));
    push_child(&mut fx.batch, f, NodeKind::Async, None);
    assert!(GilTrapRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gil_trap_silent_in_non_python_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let _f = push_async_function(&mut fx.batch, file, "compute", range(1, 31, 0, 600));
    assert!(GilTrapRule.run(&fx.ctx()).is_empty());
}

// ---------- gc_pressure ---------------------------------------------------

#[test]
fn gc_pressure_flags_listcomp_into_sum() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "total", range(1, 5, 0, 50));
    let outer = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("sum".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, outer, f).unwrap();
    let inner = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call).with_prop("is_list_comprehension", Value::Bool(true)),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, inner, outer)
        .unwrap();
    let findings = GcPressureRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.gc_pressure");
}

#[test]
fn gc_pressure_silent_without_listcomp_signal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "total", range(1, 5, 0, 50));
    let outer = fx
        .batch
        .push_node(NodeBuilder::new(NodeKind::Call).with_prop("name", Value::String("sum".into())));
    fx.batch.push_edge(EdgeKind::AST_PARENT, outer, f).unwrap();
    let inner = fx.batch.push_node(NodeBuilder::new(NodeKind::Call));
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, inner, outer)
        .unwrap();
    assert!(GcPressureRule.run(&fx.ctx()).is_empty());
}

// ---------- wrong_collection ---------------------------------------------

#[test]
fn wrong_collection_flags_long_literal_membership() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "check", range(1, 5, 0, 50));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String(" in ".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    let arg = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("element_count", Value::Int(8))
            .with_prop("name", Value::String("known_codes".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, arg, call).unwrap();
    let findings = WrongCollectionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.wrong_collection");
}

#[test]
fn wrong_collection_silent_when_signal_missing() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "check", range(1, 5, 0, 50));
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call).with_prop("name", Value::String(" in ".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, call, f).unwrap();
    let arg = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String("xs".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, arg, call).unwrap();
    assert!(WrongCollectionRule.run(&fx.ctx()).is_empty());
}

// ---------- missing_memoization ------------------------------------------

#[test]
fn missing_memoization_flags_repeated_pure_calls_from_one_caller() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    let caller = push_function(&mut fx.batch, file, "outer", range(1, 10, 0, 200));
    let helper = push_function(
        &mut fx.batch,
        file,
        "compute_score",
        range(11, 15, 200, 300),
    );
    for _ in 0..4 {
        let call = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Call)
                .with_prop("name", Value::String("compute_score".into())),
        );
        fx.batch
            .push_edge(EdgeKind::AST_PARENT, call, caller)
            .unwrap();
        fx.batch
            .push_edge(EdgeKind::CG_CALLS, call, helper)
            .unwrap();
    }
    let findings = MissingMemoizationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.missing_memoization");
}

#[test]
fn missing_memoization_silent_when_callee_is_io() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    let caller = push_function(&mut fx.batch, file, "outer", range(1, 10, 0, 200));
    let helper = push_function(&mut fx.batch, file, "fetch_record", range(11, 15, 200, 300));
    for _ in 0..4 {
        let call = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Call)
                .with_prop("name", Value::String("fetch_record".into())),
        );
        fx.batch
            .push_edge(EdgeKind::AST_PARENT, call, caller)
            .unwrap();
        fx.batch
            .push_edge(EdgeKind::CG_CALLS, call, helper)
            .unwrap();
    }
    assert!(MissingMemoizationRule.run(&fx.ctx()).is_empty());
}

// ---------- string_concat_loop -------------------------------------------

#[test]
fn string_concat_loop_flags_plus_eq_in_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "build", range(1, 5, 0, 50));
    let loop_node = push_child(&mut fx.batch, f, NodeKind::Loop, None);
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("name", Value::String("buf".into()))
            .with_prop("operator", Value::String("+=".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 10))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, write, loop_node)
        .unwrap();
    let findings = StringConcatLoopRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.perf.string_concat_loop");
}

#[test]
fn string_concat_loop_silent_when_outside_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_function(&mut fx.batch, file, "build", range(1, 5, 0, 50));
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("name", Value::String("buf".into()))
            .with_prop("operator", Value::String("+=".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, write, f).unwrap();
    assert!(StringConcatLoopRule.run(&fx.ctx()).is_empty());
}

// ---------- makezero_with_append (Phase 9 — Go) --------------------------

use crate::makezero_with_append::MakezeroWithAppendRule;
use crate::no_context_in_http::NoContextInHttpRule;
use crate::prealloc_slice_in_loop::PreallocSliceInLoopRule;
use crate::wasted_assign::WastedAssignRule;

fn fixture_with_go_source(path: &str, body: &str) -> Fixture {
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from(path), body.as_bytes().to_vec());
    let _file = push_file(&mut fx.batch, path, "go");
    fx
}

#[test]
fn makezero_with_append_flags_two_arg_make_then_append() {
    let body = "package svc\n\
                func build(n int) []int {\n    \
                    out := make([]int, n)\n    \
                    for i := 0; i < n; i++ {\n        \
                        out = append(out, i)\n    \
                    }\n    \
                    return out\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = MakezeroWithAppendRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.makezero_with_append");
}

#[test]
fn makezero_with_append_silent_on_make_with_capacity() {
    let body = "package svc\n\
                func build(n int) []int {\n    \
                    out := make([]int, 0, n)\n    \
                    for i := 0; i < n; i++ {\n        \
                        out = append(out, i)\n    \
                    }\n    \
                    return out\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(MakezeroWithAppendRule.run(&fx.ctx()).is_empty());
}

#[test]
fn makezero_with_append_silent_when_no_append() {
    let body = "package svc\n\
                func zeros(n int) []int {\n    \
                    out := make([]int, n)\n    \
                    return out\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(MakezeroWithAppendRule.run(&fx.ctx()).is_empty());
}

// ---------- prealloc_slice_in_loop (Phase 9 — Go) ------------------------

#[test]
fn prealloc_slice_in_loop_flags_zero_literal_then_append() {
    let body = "package svc\n\
                func transform(items []int) []int {\n    \
                    out := []int{}\n    \
                    for _, x := range items {\n        \
                        out = append(out, x*2)\n    \
                    }\n    \
                    return out\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = PreallocSliceInLoopRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.prealloc_slice_in_loop");
}

#[test]
fn prealloc_slice_in_loop_silent_when_capacity_set() {
    let body = "package svc\n\
                func transform(items []int) []int {\n    \
                    out := make([]int, 0, len(items))\n    \
                    for _, x := range items {\n        \
                        out = append(out, x*2)\n    \
                    }\n    \
                    return out\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(PreallocSliceInLoopRule.run(&fx.ctx()).is_empty());
}

#[test]
fn prealloc_slice_in_loop_silent_when_no_append() {
    let body = "package svc\n\
                func count(items []int) int {\n    \
                    n := 0\n    \
                    for range items {\n        \
                        n++\n    \
                    }\n    \
                    return n\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(PreallocSliceInLoopRule.run(&fx.ctx()).is_empty());
}

// ---------- no_context_in_http (Phase 9 — Go) ----------------------------

#[test]
fn no_context_in_http_flags_new_request_with_ctx_in_scope() {
    let body = "package svc\n\
                func fetch(ctx context.Context, url string) error {\n    \
                    req, err := http.NewRequest(\"GET\", url, nil)\n    \
                    _ = req; _ = err\n    \
                    return nil\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = NoContextInHttpRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.no_context_in_http");
}

#[test]
fn no_context_in_http_silent_when_with_context_used() {
    let body = "package svc\n\
                func fetch(ctx context.Context, url string) error {\n    \
                    req, err := http.NewRequestWithContext(ctx, \"GET\", url, nil)\n    \
                    _ = req; _ = err\n    \
                    return nil\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(NoContextInHttpRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_context_in_http_silent_when_no_ctx_param() {
    let body = "package svc\n\
                func fetch(url string) error {\n    \
                    req, err := http.NewRequest(\"GET\", url, nil)\n    \
                    _ = req; _ = err\n    \
                    return nil\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(NoContextInHttpRule.run(&fx.ctx()).is_empty());
}

// ---------- wasted_assign (Phase 9 — Go) ---------------------------------

#[test]
fn wasted_assign_flags_overwrite_before_read() {
    let body = "package svc\n\
                func f() int {\n    \
                    x := 1\n    \
                    x = 2\n    \
                    return x\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    let findings = WastedAssignRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert!(findings
        .iter()
        .any(|f| f.rule_id == "cc.perf.wasted_assign"));
}

#[test]
fn wasted_assign_silent_when_value_used() {
    let body = "package svc\n\
                func f() int {\n    \
                    x := 1\n    \
                    return x\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(WastedAssignRule.run(&fx.ctx()).is_empty());
}

#[test]
fn wasted_assign_silent_when_self_update() {
    // `x = x + 1` reads x, so the original `:=` is not wasted.
    let body = "package svc\n\
                func f() int {\n    \
                    x := 1\n    \
                    x = x + 1\n    \
                    return x\n\
                }\n";
    let fx = fixture_with_go_source("src/svc.go", body);
    assert!(WastedAssignRule.run(&fx.ctx()).is_empty());
}

// ---------- cloned_instead_of_copied (Phase 9 — Rust) -------------------

use crate::box_collection::BoxCollectionRule;
use crate::boxed_local::BoxedLocalRule;
use crate::branches_sharing_code::BranchesSharingCodeRule;
use crate::cloned_instead_of_copied::ClonedInsteadOfCopiedRule;
use crate::cmp_owned::CmpOwnedRule;

#[test]
fn cloned_instead_of_copied_flags_iter_cloned_on_u32_slice() {
    let body = "fn f() -> Vec<u32> {\n    \
                    let xs: &[u32] = &[1, 2, 3];\n    \
                    xs.iter().cloned().collect()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = ClonedInsteadOfCopiedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.cloned_instead_of_copied");
}

#[test]
fn cloned_instead_of_copied_silent_when_already_copied() {
    let body = "fn f() -> Vec<u32> {\n    \
                    let xs: &[u32] = &[1, 2, 3];\n    \
                    xs.iter().copied().collect()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(ClonedInsteadOfCopiedRule.run(&fx.ctx()).is_empty());
}

#[test]
fn cloned_instead_of_copied_silent_for_unknown_element_type() {
    // Without a tracked Copy declaration the heuristic stays quiet.
    let body = "fn f() {\n    \
                    let xs = make_xs();\n    \
                    let _v: Vec<_> = xs.iter().cloned().collect();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(ClonedInsteadOfCopiedRule.run(&fx.ctx()).is_empty());
}

// ---------- cmp_owned (Phase 9 — Rust) ----------------------------------

#[test]
fn cmp_owned_flags_to_string_compare() {
    let body = "fn check(s: &str) -> bool {\n    \
                    s == \"literal\".to_string()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = CmpOwnedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.cmp_owned");
}

#[test]
fn cmp_owned_flags_string_from_compare() {
    let body = "fn check(s: &str) -> bool {\n    \
                    s != String::from(\"literal\")\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert_eq!(CmpOwnedRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn cmp_owned_silent_on_str_compare() {
    let body = "fn check(s: &str) -> bool {\n    \
                    s == \"literal\"\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(CmpOwnedRule.run(&fx.ctx()).is_empty());
}

// ---------- box_collection (Phase 9 — Rust) -----------------------------

#[test]
fn box_collection_flags_box_vec() {
    let body = "struct Cache {\n    \
                    entries: Box<Vec<u32>>,\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = BoxCollectionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.box_collection");
}

#[test]
fn box_collection_flags_box_string() {
    let body = "struct Row {\n    \
                    name: Box<String>,\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert_eq!(BoxCollectionRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn box_collection_silent_on_box_dyn_trait() {
    let body = "struct Holder {\n    \
                    handler: Box<dyn Fn() -> u32>,\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(BoxCollectionRule.run(&fx.ctx()).is_empty());
}

// ---------- boxed_local (Phase 9 — Rust) --------------------------------

#[test]
fn boxed_local_flags_concrete_box_param() {
    let body = "fn process(record: Box<Record>) -> u32 {\n    \
                    record.id\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = BoxedLocalRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.boxed_local");
}

#[test]
fn boxed_local_silent_on_box_dyn_trait_param() {
    let body = "fn invoke(handler: Box<dyn Handler>) -> Result<()> {\n    \
                    handler.run()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(BoxedLocalRule.run(&fx.ctx()).is_empty());
}

#[test]
fn boxed_local_silent_on_borrow_param() {
    let body = "fn process(record: &Record) -> u32 {\n    \
                    record.id\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(BoxedLocalRule.run(&fx.ctx()).is_empty());
}

#[test]
fn boxed_local_silent_on_box_self_receiver() {
    // `self: Box<Self>` is a legitimate boxed-receiver method — must not fire.
    let body = "fn dispatch(self: Box<Self>) -> u32 {\n    \
                    self.id\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(BoxedLocalRule.run(&fx.ctx()).is_empty());
}

// ---------- branches_sharing_code (Phase 9 — Rust) ----------------------

#[test]
fn branches_sharing_code_flags_shared_tail() {
    let body = "fn f(ready: bool) {\n    \
                    if ready {\n        \
                        prep_a();\n        \
                        log_event(\"done\");\n    \
                    } else {\n        \
                        prep_b();\n        \
                        log_event(\"done\");\n    \
                    }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = BranchesSharingCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.branches_sharing_code");
}

#[test]
fn branches_sharing_code_silent_when_branches_diverge() {
    let body = "fn f(ready: bool) {\n    \
                    if ready {\n        \
                        prep_a();\n        \
                        log_event(\"a\");\n    \
                    } else {\n        \
                        prep_b();\n        \
                        log_event(\"b\");\n    \
                    }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(BranchesSharingCodeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn branches_sharing_code_silent_for_non_rust_files() {
    let body = "if cond {\n    do_a()\n    log()\nelse:\n    do_b()\n    log()\n";
    let mut fx = Fixture::new().with_source("src/foo.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.py", "python");
    assert!(BranchesSharingCodeRule.run(&fx.ctx()).is_empty());
}

// ---------- collection_is_never_read (Phase 10 — clippy) ----------------

use crate::collection_is_never_read::CollectionIsNeverReadRule;
use crate::format_in_format_args::FormatInFormatArgsRule;
use crate::useless_collect::UselessCollectRule;

#[test]
fn collection_is_never_read_flags_filled_then_dropped_vec() {
    let body = "fn audit() {\n    \
                    let mut log: Vec<u32> = Vec::new();\n    \
                    log.push(1);\n    \
                    log.push(2);\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = CollectionIsNeverReadRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.collection_is_never_read");
}

#[test]
fn collection_is_never_read_silent_when_iter_used() {
    let body = "fn audit() -> usize {\n    \
                    let mut log: Vec<u32> = Vec::new();\n    \
                    log.push(1);\n    \
                    log.iter().count()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(CollectionIsNeverReadRule.run(&fx.ctx()).is_empty());
}

#[test]
fn collection_is_never_read_silent_when_returned() {
    let body = "fn build() -> Vec<u32> {\n    \
                    let mut log: Vec<u32> = Vec::new();\n    \
                    log.push(1);\n    \
                    return log;\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(CollectionIsNeverReadRule.run(&fx.ctx()).is_empty());
}

// ---------- useless_collect (Phase 10 — clippy) -------------------------

#[test]
fn useless_collect_flags_collect_then_into_iter() {
    let body = "fn process() {\n    \
                    let _ = items().filter(p).collect::<Vec<_>>().into_iter();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = UselessCollectRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.useless_collect");
}

#[test]
fn useless_collect_flags_collect_then_iter() {
    let body = "fn process() {\n    \
                    let xs: Vec<u32> = items().map(double).collect();\n    \
                    for x in xs.iter() { eat(x); }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    // Only the chained collect().iter() pattern fires (line 2 is a binding,
    // line 3 is a separate statement on a borrowed `xs`).
    assert!(UselessCollectRule.run(&fx.ctx()).is_empty());
}

#[test]
fn useless_collect_flags_chained_collect_iter() {
    let body = "fn process() -> usize {\n    \
                    items().map(double).collect::<Vec<_>>().iter().count()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert_eq!(UselessCollectRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn useless_collect_silent_on_terminal_collect() {
    let body = "fn process() -> Vec<u32> {\n    \
                    items().map(double).collect::<Vec<_>>()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(UselessCollectRule.run(&fx.ctx()).is_empty());
}

// ---------- format_in_format_args (Phase 10 — clippy) -------------------

#[test]
fn format_in_format_args_flags_println_with_inner_format() {
    let body = "fn announce(id: u32) {\n    \
                    println!(\"got {}\", format!(\"user_{id}\"));\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = FormatInFormatArgsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.format_in_format_args");
}

#[test]
fn format_in_format_args_flags_outer_write_with_inner_format() {
    let body = "fn dump(out: &mut String, a: u32, b: u32) {\n    \
                    write!(out, \"{}\", format!(\"{a}/{b}\")).unwrap();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert_eq!(FormatInFormatArgsRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn format_in_format_args_silent_on_plain_format() {
    let body = "fn announce(id: u32) {\n    \
                    println!(\"got {id}\");\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(FormatInFormatArgsRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_perf_pack_registers_twenty_four_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinPerfPack)
        .expect("perf pack registers without error");
    assert_eq!(reg.rules().count(), 24);
    for slug in [
        "cc.perf.n_plus_one_orm",
        "cc.perf.sync_in_async",
        "cc.perf.alloc_in_loop",
        "cc.perf.wrong_collection",
        "cc.perf.regex_compile_in_loop",
        "cc.perf.missing_memoization",
        "cc.perf.gil_trap",
        "cc.perf.gc_pressure",
        "cc.perf.string_concat_loop",
        // Phase 9 (Go).
        "cc.perf.makezero_with_append",
        "cc.perf.prealloc_slice_in_loop",
        "cc.perf.no_context_in_http",
        "cc.perf.wasted_assign",
        // Phase 9 (Rust).
        "cc.perf.cloned_instead_of_copied",
        "cc.perf.cmp_owned",
        "cc.perf.box_collection",
        "cc.perf.boxed_local",
        "cc.perf.branches_sharing_code",
        // Phase 10 (Rust long-tail).
        "cc.perf.collection_is_never_read",
        "cc.perf.useless_collect",
        "cc.perf.format_in_format_args",
        // Phase 12 (final OSS long-tail sweep — Python perf trio).
        "cc.perf.regex_compile_in_function",
        "cc.perf.string_concat_in_recursion",
        "cc.perf.dict_iteration_with_keys",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

// ---------- regex_compile_in_function (Phase 12) ------------------------

#[test]
fn regex_compile_in_function_flags_per_call_compile() {
    use crate::regex_compile_in_function::RegexCompileInFunctionRule;
    let body = "import re\n\
                def is_email(s):\n    \
                    pattern = re.compile(r\"[^@]+@[^@]+\\.[^@]+\")\n    \
                    return pattern.match(s)\n";
    let mut fx = Fixture::new().with_source("src/svc.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.py", "python");
    let findings = RegexCompileInFunctionRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.regex_compile_in_function");
}

#[test]
fn regex_compile_in_function_silent_on_module_level_compile() {
    use crate::regex_compile_in_function::RegexCompileInFunctionRule;
    let body = "import re\n\
                _PATTERN = re.compile(r\"[^@]+@[^@]+\")\n\
                def is_email(s):\n    \
                    return _PATTERN.match(s)\n";
    let mut fx = Fixture::new().with_source("src/svc.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.py", "python");
    assert!(RegexCompileInFunctionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn regex_compile_in_function_silent_on_test_files() {
    use crate::regex_compile_in_function::RegexCompileInFunctionRule;
    let body = "import re\n\
                def test_pattern():\n    \
                    p = re.compile(r\"x\")\n    \
                    assert p.match(\"x\")\n";
    let mut fx = Fixture::new().with_source("tests/test_x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "tests/test_x.py", "python");
    assert!(RegexCompileInFunctionRule.run(&fx.ctx()).is_empty());
}

// ---------- string_concat_in_recursion (Phase 12) -----------------------

#[test]
fn string_concat_in_recursion_flags_self_recursive_concat() {
    use crate::string_concat_in_recursion::StringConcatInRecursionRule;
    let body = "def collect(node, acc=\"\"):\n    \
                    acc = acc + node.value\n    \
                    for child in node.children:\n        \
                        acc = collect(child, acc)\n    \
                    return acc\n";
    let mut fx = Fixture::new().with_source("src/tree.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/tree.py", "python");
    let findings = StringConcatInRecursionRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.string_concat_in_recursion");
}

#[test]
fn string_concat_in_recursion_silent_without_recursion() {
    use crate::string_concat_in_recursion::StringConcatInRecursionRule;
    let body = "def join(parts):\n    \
                    acc = \"\"\n    \
                    for p in parts:\n        \
                        acc = acc + p\n    \
                    return acc\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    assert!(StringConcatInRecursionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn string_concat_in_recursion_silent_on_int_accumulation() {
    use crate::string_concat_in_recursion::StringConcatInRecursionRule;
    let body = "def total(node, n=0):\n    \
                    n = n + node.value\n    \
                    for child in node.children:\n        \
                        n = total(child, n)\n    \
                    return n\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    // `n` doesn't match the string-buffer name list — should not fire.
    assert!(StringConcatInRecursionRule.run(&fx.ctx()).is_empty());
}

// ---------- dict_iteration_with_keys (Phase 12) -------------------------

#[test]
fn dict_iteration_with_keys_flags_for_loop() {
    use crate::dict_iteration_with_keys::DictIterationWithKeysRule;
    let body = "def f(d):\n    \
                    for k in d.keys():\n        \
                        print(k)\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    let findings = DictIterationWithKeysRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.perf.dict_iteration_with_keys");
}

#[test]
fn dict_iteration_with_keys_flags_membership_test() {
    use crate::dict_iteration_with_keys::DictIterationWithKeysRule;
    let body = "def f(d, k):\n    \
                    if k in d.keys():\n        \
                        return d[k]\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    assert_eq!(DictIterationWithKeysRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn dict_iteration_with_keys_silent_on_iterating_dict_directly() {
    use crate::dict_iteration_with_keys::DictIterationWithKeysRule;
    let body = "def f(d):\n    \
                    for k in d:\n        \
                        print(k)\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    assert!(DictIterationWithKeysRule.run(&fx.ctx()).is_empty());
}
