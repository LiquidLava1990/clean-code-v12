//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real rule has at least one positive (violating) and one
//! negative (clean) case. The stub probe has a registration-only test.
//! The pack-level test confirms every rule registers and resolves.

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::async_returns_null::AsyncReturnsNullRule;
use crate::await_thenable::AwaitThenableRule;
use crate::ban_ts_comment::BanTsCommentRule;
use crate::consistent_type_imports::ConsistentTypeImportsRule;
use crate::exhaustruct::ExhaustructRule;
use crate::implicit_any::ImplicitAnyRule;
use crate::lock_held_across_await::LockHeldAcrossAwaitRule;
use crate::no_base_to_string::NoBaseToStringRule;
use crate::no_confusing_void_expression::NoConfusingVoidExpressionRule;
use crate::no_explicit_any::NoExplicitAnyRule;
use crate::no_floating_promise::NoFloatingPromiseRule;
use crate::no_misused_promise::NoMisusedPromiseRule;
use crate::no_non_null_assertion::NoNonNullAssertionRule;
use crate::no_unnecessary_condition::NoUnnecessaryConditionRule;
use crate::no_unsafe_argument::NoUnsafeArgumentRule;
use crate::no_unsafe_enum_comparison::NoUnsafeEnumComparisonRule;
use crate::no_unsafe_return::NoUnsafeReturnRule;
use crate::no_unused_expressions::NoUnusedExpressionsRule;
use crate::no_var_requires::NoVarRequiresRule;
use crate::protocol_drift::ProtocolDriftRule;
use crate::strict_boolean_expressions::StrictBooleanExpressionsRule;
use crate::switch_exhaustiveness::SwitchExhaustivenessRule;
use crate::unjustified_ignore::UnjustifiedIgnoreRule;
use crate::BuiltinTypesPack;

// ---------- shared fixtures ----------------------------------------------

const fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

const fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str, language: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String(language.to_owned())),
    )
}

struct FnSpec<'a> {
    name: &'a str,
    return_type: Option<&'a str>,
    is_pub: bool,
    rng: Range,
}

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, spec: FnSpec<'_>) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Function)
        .with_prop("name", Value::String(spec.name.to_owned()))
        .with_prop("range", Value::Range(spec.rng))
        .with_prop("is_pub", Value::Bool(spec.is_pub));
    if let Some(rt) = spec.return_type {
        builder = builder.with_prop("return_type", Value::String(rt.to_owned()));
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_param(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    type_annotation: Option<&str>,
    rng: Range,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Parameter)
        .with_prop("name", Value::String(name.to_owned()))
        .with_prop("range", Value::Range(rng));
    if let Some(t) = type_annotation {
        builder = builder.with_prop("type", Value::String(t.to_owned()));
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_comment(batch: &mut CpgWriteBatch, parent: NodeId, text: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Comment)
            .with_prop("text", Value::String(text.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_block(batch: &mut CpgWriteBatch, parent: NodeId, rng: Range) -> NodeId {
    let id =
        batch.push_node(NodeBuilder::new(NodeKind::Block).with_prop("range", Value::Range(rng)));
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_branch_with_condition(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    condition: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Branch)
            .with_prop("condition", Value::String(condition.to_owned()))
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

// ---------- implicit_any -------------------------------------------------

#[test]
fn implicit_any_flags_python_any_return() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let func = push_function(
        &mut fx.batch,
        file,
        FnSpec {
            name: "load_blob",
            return_type: Some("Any"),
            is_pub: true,
            rng: range(1, 1, 0, 30),
        },
    );
    push_param(&mut fx.batch, func, "key", Some("str"), range(1, 1, 10, 20));
    let findings = ImplicitAnyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.implicit_any");
}

#[test]
fn implicit_any_flags_typescript_any_param() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("load".into()))
            .with_prop("return_type", Value::String("Promise<User>".into()))
            .with_prop("is_export", Value::Bool(true))
            .with_prop("range", Value::Range(range(1, 1, 0, 40))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    push_param(
        &mut fx.batch,
        func,
        "payload",
        Some("any"),
        range(1, 1, 5, 15),
    );
    let findings = ImplicitAnyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].message.headline.contains("payload"));
}

#[test]
fn implicit_any_silent_on_typed_public_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let func = push_function(
        &mut fx.batch,
        file,
        FnSpec {
            name: "load_user",
            return_type: Some("User"),
            is_pub: true,
            rng: range(1, 1, 0, 30),
        },
    );
    push_param(&mut fx.batch, func, "key", Some("str"), range(1, 1, 10, 20));
    assert!(ImplicitAnyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn implicit_any_silent_on_private_python_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let func = push_function(
        &mut fx.batch,
        file,
        FnSpec {
            name: "_helper",
            return_type: Some("Any"),
            is_pub: false,
            rng: range(1, 1, 0, 30),
        },
    );
    push_param(&mut fx.batch, func, "x", Some("Any"), range(1, 1, 10, 20));
    assert!(ImplicitAnyRule.run(&fx.ctx()).is_empty());
}

// ---------- unjustified_ignore ------------------------------------------

#[test]
fn unjustified_ignore_flags_bare_ts_ignore() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_comment(&mut fx.batch, file, "// @ts-ignore", range(1, 1, 0, 13));
    let findings = UnjustifiedIgnoreRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.unjustified_ignore");
}

#[test]
fn unjustified_ignore_silent_when_reason_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_comment(
        &mut fx.batch,
        file,
        "// @ts-ignore: upstream bug 1234, fix tracked",
        range(1, 1, 0, 45),
    );
    assert!(UnjustifiedIgnoreRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unjustified_ignore_flags_bare_python_type_ignore() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_comment(&mut fx.batch, file, "# type: ignore", range(1, 1, 0, 14));
    let findings = UnjustifiedIgnoreRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn unjustified_ignore_silent_on_python_with_because() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_comment(
        &mut fx.batch,
        file,
        "# type: ignore because pyright misreads tree-sitter return",
        range(1, 1, 0, 60),
    );
    assert!(UnjustifiedIgnoreRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unjustified_ignore_flags_bare_rust_allow() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    push_comment(
        &mut fx.batch,
        file,
        "#[allow(dead_code)]",
        range(1, 1, 0, 19),
    );
    let findings = UnjustifiedIgnoreRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn unjustified_ignore_silent_on_rust_allow_with_reason() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.rs", "rust");
    push_comment(
        &mut fx.batch,
        file,
        "#[allow(dead_code, reason = \"Phase-4 wiring\")]",
        range(1, 1, 0, 46),
    );
    assert!(UnjustifiedIgnoreRule.run(&fx.ctx()).is_empty());
}

// ---------- protocol_drift (stub) ---------------------------------------

#[test]
fn protocol_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(ProtocolDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- no_floating_promise -----------------------------------------

#[test]
fn no_floating_promise_flags_bare_async_call_in_block() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/handler.ts", "typescript");
    let block = push_block(&mut fx.batch, file, range(1, 5, 0, 80));
    push_call(&mut fx.batch, block, "fetch(url)", range(2, 2, 10, 20));
    let findings = NoFloatingPromiseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_floating_promise");
}

#[test]
fn no_floating_promise_silent_when_call_under_async_await() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/handler.ts", "typescript");
    let block = push_block(&mut fx.batch, file, range(1, 5, 0, 80));
    let await_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Async)
            .with_prop("kind", Value::String("await".into()))
            .with_prop("range", Value::Range(range(2, 2, 10, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, await_node, block)
        .unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("fetch(url)".into()))
            .with_prop("range", Value::Range(range(2, 2, 16, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, await_node)
        .unwrap();
    assert!(NoFloatingPromiseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_floating_promise_flags_async_suffix_callee() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/handler.ts", "typescript");
    let block = push_block(&mut fx.batch, file, range(1, 5, 0, 80));
    push_call(&mut fx.batch, block, "saveDataAsync()", range(2, 2, 0, 16));
    let findings = NoFloatingPromiseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- no_misused_promise ------------------------------------------

#[test]
fn no_misused_promise_flags_async_call_in_if() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/router.ts", "typescript");
    push_branch_with_condition(&mut fx.batch, file, "isReadyAsync()", range(3, 3, 0, 40));
    let findings = NoMisusedPromiseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_misused_promise");
}

#[test]
fn no_misused_promise_silent_on_awaited_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/router.ts", "typescript");
    push_branch_with_condition(
        &mut fx.batch,
        file,
        "await isReadyAsync()",
        range(3, 3, 0, 40),
    );
    assert!(NoMisusedPromiseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_misused_promise_flags_fetch_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/router.ts", "typescript");
    push_branch_with_condition(&mut fx.batch, file, "fetch(url)", range(3, 3, 0, 30));
    let findings = NoMisusedPromiseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- no_unsafe_argument ------------------------------------------

#[test]
fn no_unsafe_argument_flags_as_any_cast() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/api.ts", "typescript");
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("save".into()))
            .with_prop("arguments", Value::String("(payload as any)".into()))
            .with_prop("range", Value::Range(range(4, 4, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoUnsafeArgumentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_unsafe_argument");
}

#[test]
fn no_unsafe_argument_silent_on_typed_argument() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/api.ts", "typescript");
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("save".into()))
            .with_prop("arguments", Value::String("(payload)".into()))
            .with_prop("range", Value::Range(range(4, 4, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    assert!(NoUnsafeArgumentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_unsafe_argument_flags_any_typed_local() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/api.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("blob".into()))
            .with_prop("type", Value::String("any".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("save".into()))
            .with_prop("arguments", Value::String("(blob)".into()))
            .with_prop("range", Value::Range(range(4, 4, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoUnsafeArgumentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- no_unsafe_return --------------------------------------------

#[test]
fn no_unsafe_return_flags_as_any_in_typed_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("return_type", Value::String("User".into()))
            .with_prop(
                "return_expressions",
                Value::String("return data as any;".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    let findings = NoUnsafeReturnRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_unsafe_return");
}

#[test]
fn no_unsafe_return_silent_when_return_is_typed() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("return_type", Value::String("User".into()))
            .with_prop(
                "return_expressions",
                Value::String("return UserSchema.parse(data);".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    assert!(NoUnsafeReturnRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_unsafe_return_silent_when_return_type_is_any() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("return_type", Value::String("any".into()))
            .with_prop(
                "return_expressions",
                Value::String("return data as any;".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    // Declared return type is `any`, so casting to `any` is consistent.
    assert!(NoUnsafeReturnRule.run(&fx.ctx()).is_empty());
}

// ---------- switch_exhaustiveness ---------------------------------------

#[test]
fn switch_exhaustiveness_flags_ts_switch_without_default() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let branch = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Branch)
            .with_prop("kind", Value::String("switch".into()))
            .with_prop("discriminant", Value::String("status".into()))
            .with_prop("cases", Value::String("case 'open': case 'closed':".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, branch, file)
        .unwrap();
    let findings = SwitchExhaustivenessRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.switch_exhaustiveness");
}

#[test]
fn switch_exhaustiveness_silent_with_default() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let branch = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Branch)
            .with_prop("kind", Value::String("switch".into()))
            .with_prop("discriminant", Value::String("status".into()))
            .with_prop(
                "cases",
                Value::String("case 'open': case 'closed': default:".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, branch, file)
        .unwrap();
    assert!(SwitchExhaustivenessRule.run(&fx.ctx()).is_empty());
}

#[test]
fn switch_exhaustiveness_silent_when_only_one_case() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let branch = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Branch)
            .with_prop("kind", Value::String("switch".into()))
            .with_prop("discriminant", Value::String("status".into()))
            .with_prop("cases", Value::String("case 'open':".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, branch, file)
        .unwrap();
    assert!(SwitchExhaustivenessRule.run(&fx.ctx()).is_empty());
}

// ---------- lock_held_across_await --------------------------------------

#[test]
fn lock_held_across_await_flags_lock_then_await() {
    let mut fx = Fixture::new();
    let path_str = "src/server.rs";
    let file = push_file(&mut fx.batch, path_str, "rust");
    let body = "async fn handle() {\n    let g = m.lock();\n    next.await;\n}\n";
    let bytes = body.as_bytes();
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("handle".into()))
            .with_prop("is_async", Value::Bool(true))
            .with_prop("range", Value::Range(range(1, 4, 0, bytes.len() as u32))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    fx.source
        .insert(camino::Utf8PathBuf::from(path_str), bytes.to_vec());
    let findings = LockHeldAcrossAwaitRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.lock_held_across_await");
}

#[test]
fn lock_held_across_await_silent_when_lock_dropped_before_await() {
    let mut fx = Fixture::new();
    let path_str = "src/server.rs";
    let file = push_file(&mut fx.batch, path_str, "rust");
    let body = "async fn handle() {\n    { let g = m.lock(); use(g); };\n    next.await;\n}\n";
    let bytes = body.as_bytes();
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("handle".into()))
            .with_prop("is_async", Value::Bool(true))
            .with_prop("range", Value::Range(range(1, 4, 0, bytes.len() as u32))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    fx.source
        .insert(camino::Utf8PathBuf::from(path_str), bytes.to_vec());
    assert!(LockHeldAcrossAwaitRule.run(&fx.ctx()).is_empty());
}

#[test]
fn lock_held_across_await_silent_on_non_async_function() {
    let mut fx = Fixture::new();
    let path_str = "src/server.rs";
    let file = push_file(&mut fx.batch, path_str, "rust");
    let body = "fn handle() {\n    let g = m.lock();\n    next.await;\n}\n";
    let bytes = body.as_bytes();
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("handle".into()))
            .with_prop("is_async", Value::Bool(false))
            .with_prop("range", Value::Range(range(1, 4, 0, bytes.len() as u32))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    fx.source
        .insert(camino::Utf8PathBuf::from(path_str), bytes.to_vec());
    assert!(LockHeldAcrossAwaitRule.run(&fx.ctx()).is_empty());
}

// ---------- async_returns_null ------------------------------------------

#[test]
fn async_returns_null_flags_null_return_with_typed_promise() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("is_async", Value::Bool(true))
            .with_prop("return_type", Value::String("Promise<User>".into()))
            .with_prop("return_expressions", Value::String("return null;".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    let findings = AsyncReturnsNullRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.async_returns_null");
}

#[test]
fn async_returns_null_silent_when_return_type_allows_null() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("is_async", Value::Bool(true))
            .with_prop("return_type", Value::String("Promise<User | null>".into()))
            .with_prop("return_expressions", Value::String("return null;".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    assert!(AsyncReturnsNullRule.run(&fx.ctx()).is_empty());
}

#[test]
fn async_returns_null_silent_when_no_null_return() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/load.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadUser".into()))
            .with_prop("is_async", Value::Bool(true))
            .with_prop("return_type", Value::String("Promise<User>".into()))
            .with_prop("return_expressions", Value::String("return user;".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    assert!(AsyncReturnsNullRule.run(&fx.ctx()).is_empty());
}

// ---------- await_thenable ----------------------------------------------

#[test]
fn await_thenable_flags_await_number_literal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let async_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Async)
            .with_prop("kind", Value::String("await".into()))
            .with_prop("expression", Value::String("42".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 8))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, async_node, file)
        .unwrap();
    let findings = AwaitThenableRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.await_thenable");
}

#[test]
fn await_thenable_flags_await_object_literal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let async_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Async)
            .with_prop("kind", Value::String("await".into()))
            .with_prop("expression", Value::String("{ foo: 1 }".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 16))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, async_node, file)
        .unwrap();
    let findings = AwaitThenableRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn await_thenable_silent_on_await_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let async_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Async)
            .with_prop("kind", Value::String("await".into()))
            .with_prop("expression", Value::String("fetch(url)".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 16))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, async_node, file)
        .unwrap();
    assert!(AwaitThenableRule.run(&fx.ctx()).is_empty());
}

// ---------- no_unnecessary_condition ------------------------------------

#[test]
fn no_unnecessary_condition_flags_if_true() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    push_branch_with_condition(&mut fx.batch, file, "true", range(1, 1, 0, 6));
    let findings = NoUnnecessaryConditionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_unnecessary_condition");
}

#[test]
fn no_unnecessary_condition_flags_doubled_undefined_check() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    push_branch_with_condition(
        &mut fx.batch,
        file,
        "x !== undefined && x !== undefined",
        range(1, 1, 0, 40),
    );
    let findings = NoUnnecessaryConditionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn no_unnecessary_condition_silent_on_real_predicate() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    push_branch_with_condition(&mut fx.batch, file, "user !== null", range(1, 1, 0, 14));
    assert!(NoUnnecessaryConditionRule.run(&fx.ctx()).is_empty());
}

// ---------- exhaustruct -------------------------------------------------

#[test]
fn exhaustruct_flags_missing_slice_field() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/order.go", "go");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Order".into()))
            .with_prop(
                "fields_declared",
                Value::String("ID:int, Items:[]Item, Total:float64".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("kind", Value::String("struct_literal".into()))
            .with_prop("type_name", Value::String("Order".into()))
            .with_prop("fields_set", Value::String("ID:1, Total:9.99".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 140))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    let findings = ExhaustructRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.exhaustruct");
    assert!(findings[0].message.headline.contains("Items"));
}

#[test]
fn exhaustruct_silent_when_only_zeroable_missing() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/order.go", "go");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Order".into()))
            .with_prop(
                "fields_declared",
                Value::String("ID:int, Total:float64".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("kind", Value::String("struct_literal".into()))
            .with_prop("type_name", Value::String("Order".into()))
            .with_prop("fields_set", Value::String("ID:1".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 140))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    assert!(ExhaustructRule.run(&fx.ctx()).is_empty());
}

#[test]
fn exhaustruct_silent_when_all_set() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/order.go", "go");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Order".into()))
            .with_prop(
                "fields_declared",
                Value::String("ID:int, Items:[]Item".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("kind", Value::String("struct_literal".into()))
            .with_prop("type_name", Value::String("Order".into()))
            .with_prop("fields_set", Value::String("ID:1, Items:nil".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 140))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    assert!(ExhaustructRule.run(&fx.ctx()).is_empty());
}

// ---------- no_explicit_any ---------------------------------------------

#[test]
fn no_explicit_any_flags_param_annotation() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/api.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("save".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    push_param(
        &mut fx.batch,
        func,
        "payload",
        Some("any"),
        range(1, 1, 5, 15),
    );
    let findings = NoExplicitAnyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_explicit_any");
}

#[test]
fn no_explicit_any_flags_variable_annotation() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/store.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("blob".into()))
            .with_prop("type", Value::String("any".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 18))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let findings = NoExplicitAnyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn no_explicit_any_silent_when_typed() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/api.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("save".into()))
            .with_prop("return_type", Value::String("Promise<User>".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    push_param(
        &mut fx.batch,
        func,
        "payload",
        Some("Payload"),
        range(1, 1, 5, 15),
    );
    assert!(NoExplicitAnyRule.run(&fx.ctx()).is_empty());
}

// ---------- no_non_null_assertion ---------------------------------------

#[test]
fn no_non_null_assertion_flags_member_access() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/feature.ts", "typescript");
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("doIt".into()))
            .with_prop("expression", Value::String("user!.name".into()))
            .with_prop("range", Value::Range(range(2, 2, 0, 12))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoNonNullAssertionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_non_null_assertion");
}

#[test]
fn no_non_null_assertion_silent_on_inequality() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/feature.ts", "typescript");
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("doIt".into()))
            .with_prop(
                "expression",
                Value::String("if (a !== b) { return; }".into()),
            )
            .with_prop("range", Value::Range(range(2, 2, 0, 24))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    assert!(NoNonNullAssertionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_non_null_assertion_flags_postfix_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/feature.ts", "typescript");
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("doIt".into()))
            .with_prop("expression", Value::String("getCallback()!()".into()))
            .with_prop("range", Value::Range(range(3, 3, 0, 18))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoNonNullAssertionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- strict_boolean_expressions ----------------------------------

#[test]
fn strict_boolean_expressions_flags_string_local_in_if() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/check.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("name".into()))
            .with_prop("type", Value::String("string".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    push_branch_with_condition(&mut fx.batch, file, "name", range(2, 2, 0, 6));
    let findings = StrictBooleanExpressionsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.strict_boolean_expressions");
}

#[test]
fn strict_boolean_expressions_silent_on_explicit_compare() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/check.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("name".into()))
            .with_prop("type", Value::String("string".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    push_branch_with_condition(&mut fx.batch, file, "name.length > 0", range(2, 2, 0, 16));
    assert!(StrictBooleanExpressionsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn strict_boolean_expressions_flags_number_local() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/check.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("count".into()))
            .with_prop("type", Value::String("number".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    push_branch_with_condition(&mut fx.batch, file, "count", range(2, 2, 0, 6));
    let findings = StrictBooleanExpressionsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

// ---------- no_base_to_string -------------------------------------------

#[test]
fn no_base_to_string_flags_template_interpolation() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/log.ts", "typescript");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Order".into()))
            .with_prop("methods_declared", Value::String("create(): void".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("o".into()))
            .with_prop("type", Value::String("Order".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 110))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("log".into()))
            .with_prop("expression", Value::String("`order ${o} ready`".into()))
            .with_prop("range", Value::Range(range(8, 8, 120, 140))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoBaseToStringRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_base_to_string");
}

#[test]
fn no_base_to_string_silent_when_class_has_to_string() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/log.ts", "typescript");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Order".into()))
            .with_prop(
                "methods_declared",
                Value::String("create(): void; toString(): string".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("o".into()))
            .with_prop("type", Value::String("Order".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 110))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("log".into()))
            .with_prop("expression", Value::String("`order ${o} ready`".into()))
            .with_prop("range", Value::Range(range(8, 8, 120, 140))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    assert!(NoBaseToStringRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_base_to_string_flags_string_call_coercion() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/log.ts", "typescript");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("User".into()))
            .with_prop("methods_declared", Value::String("greet(): void".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("u".into()))
            .with_prop("type", Value::String("User".into()))
            .with_prop("range", Value::Range(range(7, 7, 100, 110))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("log".into()))
            .with_prop("expression", Value::String("String(u)".into()))
            .with_prop("range", Value::Range(range(8, 8, 120, 140))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoBaseToStringRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- no_confusing_void_expression --------------------------------

#[test]
fn no_confusing_void_expression_flags_arrow_void() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/h.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("handler".into()))
            .with_prop(
                "expression",
                Value::String("() => void doSomething()".into()),
            )
            .with_prop("range", Value::Range(range(1, 1, 0, 40))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let findings = NoConfusingVoidExpressionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_confusing_void_expression");
}

#[test]
fn no_confusing_void_expression_flags_return_void() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/h.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("g".into()))
            .with_prop(
                "return_expressions",
                Value::String("return void compute();".into()),
            )
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    let findings = NoConfusingVoidExpressionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn no_confusing_void_expression_silent_on_void_type() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/h.ts", "typescript");
    let func = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("g".into()))
            .with_prop("return_type", Value::String("void".into()))
            .with_prop("return_expressions", Value::String("return;".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, func, file)
        .unwrap();
    assert!(NoConfusingVoidExpressionRule.run(&fx.ctx()).is_empty());
}

// ---------- no_unsafe_enum_comparison -----------------------------------

#[test]
fn no_unsafe_enum_comparison_flags_cross_enum_check() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let _enum_a = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Status".into()))
            .with_prop("kind", Value::String("enum".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 40))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, _enum_a, file)
        .unwrap();
    let _enum_b = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Phase".into()))
            .with_prop("kind", Value::String("enum".into()))
            .with_prop("range", Value::Range(range(7, 11, 50, 90))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, _enum_b, file)
        .unwrap();
    push_branch_with_condition(
        &mut fx.batch,
        file,
        "Status.OPEN === Phase.OPEN",
        range(13, 13, 100, 130),
    );
    let findings = NoUnsafeEnumComparisonRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_unsafe_enum_comparison");
}

#[test]
fn no_unsafe_enum_comparison_silent_on_same_enum() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let e = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Status".into()))
            .with_prop("kind", Value::String("enum".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 40))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, e, file).unwrap();
    let e2 = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Phase".into()))
            .with_prop("kind", Value::String("enum".into()))
            .with_prop("range", Value::Range(range(7, 11, 50, 90))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, e2, file).unwrap();
    push_branch_with_condition(
        &mut fx.batch,
        file,
        "Status.OPEN === Status.CLOSED",
        range(13, 13, 100, 130),
    );
    assert!(NoUnsafeEnumComparisonRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_unsafe_enum_comparison_silent_when_not_enum_class() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/state.ts", "typescript");
    let regular = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Status".into()))
            .with_prop("kind", Value::String("class".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 40))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, regular, file)
        .unwrap();
    push_branch_with_condition(
        &mut fx.batch,
        file,
        "Status.OPEN === Phase.OPEN",
        range(13, 13, 100, 130),
    );
    assert!(NoUnsafeEnumComparisonRule.run(&fx.ctx()).is_empty());
}

// ---------- ban_ts_comment ----------------------------------------------

#[test]
fn ban_ts_comment_flags_bare_ts_ignore() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_comment(&mut fx.batch, file, "// @ts-ignore", range(1, 1, 0, 13));
    let findings = BanTsCommentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.ban_ts_comment");
}

#[test]
fn ban_ts_comment_silent_when_described() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_comment(
        &mut fx.batch,
        file,
        "// @ts-ignore: upstream issue 123 fix tracked",
        range(1, 1, 0, 50),
    );
    assert!(BanTsCommentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn ban_ts_comment_flags_short_description() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_comment(
        &mut fx.batch,
        file,
        "// @ts-expect-error: x",
        range(1, 1, 0, 24),
    );
    let findings = BanTsCommentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- no_unused_expressions ---------------------------------------

#[test]
fn no_unused_expressions_flags_bare_identifier() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let block = push_block(&mut fx.batch, file, range(1, 5, 0, 40));
    let ident = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Identifier)
            .with_prop("name", Value::String("x".into()))
            .with_prop("range", Value::Range(range(2, 2, 10, 12))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, ident, block)
        .unwrap();
    let findings = NoUnusedExpressionsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_unused_expressions");
}

#[test]
fn no_unused_expressions_silent_on_use_strict_directive() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String("\"use strict\"".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 14))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    assert!(NoUnusedExpressionsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_unused_expressions_silent_on_call_expression() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/x.ts", "typescript");
    let block = push_block(&mut fx.batch, file, range(1, 5, 0, 40));
    let read = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Read)
            .with_prop("expression", Value::String("doIt()".into()))
            .with_prop("range", Value::Range(range(2, 2, 10, 18))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, read, block)
        .unwrap();
    assert!(NoUnusedExpressionsRule.run(&fx.ctx()).is_empty());
}

// ---------- no_var_requires ---------------------------------------------

#[test]
fn no_var_requires_flags_require_in_ts_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/loader.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("fs".into()))
            .with_prop("expression", Value::String("require('fs')".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 24))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let findings = NoVarRequiresRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.no_var_requires");
}

#[test]
fn no_var_requires_silent_on_cjs_extension() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/loader.cjs", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("fs".into()))
            .with_prop("expression", Value::String("require('fs')".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 24))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    assert!(NoVarRequiresRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_var_requires_silent_on_esm_import() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/loader.ts", "typescript");
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("fs".into()))
            .with_prop("expression", Value::String("import('fs')".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 24))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    assert!(NoVarRequiresRule.run(&fx.ctx()).is_empty());
}

// ---------- consistent_type_imports -------------------------------------

#[test]
fn consistent_type_imports_flags_type_only_named_import() {
    let mut fx = Fixture::new();
    let path = "src/feature.ts";
    let file = push_file(&mut fx.batch, path, "typescript");
    let _ = file;
    let body = "import { Foo } from './foo';\nfunction make(): Foo { throw new Error('x'); }\n";
    fx.source
        .insert(camino::Utf8PathBuf::from(path), body.as_bytes().to_vec());
    let findings = ConsistentTypeImportsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.type.consistent_type_imports");
}

#[test]
fn consistent_type_imports_silent_on_value_use() {
    let mut fx = Fixture::new();
    let path = "src/feature.ts";
    let _file = push_file(&mut fx.batch, path, "typescript");
    let body = "import { Foo } from './foo';\nconst x = new Foo();\nexport default x;\n";
    fx.source
        .insert(camino::Utf8PathBuf::from(path), body.as_bytes().to_vec());
    assert!(ConsistentTypeImportsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn consistent_type_imports_silent_when_already_type_only() {
    let mut fx = Fixture::new();
    let path = "src/feature.ts";
    let _file = push_file(&mut fx.batch, path, "typescript");
    let body =
        "import type { Foo } from './foo';\nfunction make(): Foo { throw new Error('x'); }\n";
    fx.source
        .insert(camino::Utf8PathBuf::from(path), body.as_bytes().to_vec());
    assert!(ConsistentTypeImportsRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_all_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTypesPack)
        .expect("Family-22 pack registers without error");
    let expected_slugs = [
        "cc.type.implicit_any",
        "cc.type.unjustified_ignore",
        "cc.type.protocol_drift",
        "cc.type.no_floating_promise",
        "cc.type.no_misused_promise",
        "cc.type.no_unsafe_argument",
        "cc.type.no_unsafe_return",
        "cc.type.switch_exhaustiveness",
        "cc.bug.lock_held_across_await",
        "cc.type.async_returns_null",
        "cc.type.await_thenable",
        "cc.type.no_unnecessary_condition",
        "cc.type.exhaustruct",
        "cc.type.no_explicit_any",
        "cc.type.no_non_null_assertion",
        "cc.type.strict_boolean_expressions",
        "cc.type.no_base_to_string",
        "cc.type.no_confusing_void_expression",
        "cc.type.no_unsafe_enum_comparison",
        "cc.type.ban_ts_comment",
        "cc.type.no_unused_expressions",
        "cc.type.no_var_requires",
        "cc.type.consistent_type_imports",
    ];
    assert_eq!(reg.rules().count(), expected_slugs.len());
    for slug in expected_slugs {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
