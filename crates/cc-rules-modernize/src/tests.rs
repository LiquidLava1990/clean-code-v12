//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe ships a positive (violating), a negative (clean),
//! and a test-file-skip case. The single stub probe
//! [`SyncInAsyncRuntimeRule`] exercises a registration-only test —
//! it returns `Vec::new()` until the phase-7 frontend signal lands.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::bare_reraise_lossy::BareReraiseLossyRule;
use crate::callbacks_over_promises::CallbacksOverPromisesRule;
use crate::commonjs_require::CommonjsRequireRule;
use crate::consistent_function_scoping::ConsistentFunctionScopingRule;
use crate::deprecated_typing_alias::DeprecatedTypingAliasRule;
use crate::deprecated_unittest_aliases::DeprecatedUnittestAliasesRule;
use crate::deprecated_unwrap::DeprecatedUnwrapRule;
use crate::dict_literal_over_call::DictLiteralOverCallRule;
use crate::legacy_format_macro::LegacyFormatMacroRule;
use crate::list_call_in_set_call::ListCallInSetCallRule;
use crate::no_array_for_each::NoArrayForEachRule;
use crate::os_path_join::OsPathJoinRule;
use crate::simplify_boolean_expr::SimplifyBooleanExprRule;
use crate::string_format_legacy::StringFormatLegacyRule;
use crate::string_format_to_fstring::StringFormatToFstringRule;
use crate::sync_in_async_runtime::SyncInAsyncRuntimeRule;
use crate::template_over_concat::TemplateOverConcatRule;
use crate::thread_spawn_no_join::ThreadSpawnNoJoinRule;
use crate::use_pathlib_over_os::UsePathlibOverOsRule;
use crate::var_for_let::VarForLetRule;
use crate::BuiltinModernizePack;

// ---------- shared fixtures ---------------------------------------------

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

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

/// Spec for [`push_call_with`] — fields beat a 6-arg positional list.
struct CallWithSpec<'a> {
    parent: NodeId,
    callee: &'a str,
    extra_key: &'a str,
    extra_val: &'a str,
    rng: Range,
}

fn push_call_with(batch: &mut CpgWriteBatch, spec: CallWithSpec<'_>) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(spec.callee.to_owned()))
            .with_prop(spec.extra_key, Value::String(spec.extra_val.to_owned()))
            .with_prop("range", Value::Range(spec.rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, spec.parent)
        .unwrap();
    id
}

// ---------- string_format_legacy (now %-only after Phase 8 split) -------

#[test]
fn string_format_legacy_flags_percent_formatting() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "log",
            extra_key: "text",
            extra_val: "\"hello %s\" % name",
            rng: range(1, 1, 0, 18),
        },
    );
    let findings = StringFormatLegacyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.string_format_legacy");
}

#[test]
fn string_format_legacy_silent_on_fstring() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(
        &mut fx.batch,
        file,
        "print(f\"hello {name}\")",
        range(1, 1, 0, 24),
    );
    assert!(StringFormatLegacyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn string_format_legacy_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "log",
            extra_key: "text",
            extra_val: "\"hi %s\" % x",
            rng: range(1, 1, 0, 12),
        },
    );
    assert!(StringFormatLegacyRule.run(&fx.ctx()).is_empty());
}

// ---------- deprecated_typing_alias -------------------------------------

#[test]
fn deprecated_typing_alias_flags_typing_list() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Type)
            .with_prop("qualified", Value::String("typing.List".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 11))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    let findings = DeprecatedTypingAliasRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.deprecated_typing_alias");
}

#[test]
fn deprecated_typing_alias_silent_on_builtin_list() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Type)
            .with_prop("qualified", Value::String("list".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 4))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(DeprecatedTypingAliasRule.run(&fx.ctx()).is_empty());
}

#[test]
fn deprecated_typing_alias_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_x.py", "python");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Type)
            .with_prop("qualified", Value::String("typing.Dict".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 11))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(DeprecatedTypingAliasRule.run(&fx.ctx()).is_empty());
}

// ---------- os_path_join ------------------------------------------------

#[test]
fn os_path_join_flags_join_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "os.path.join", range(1, 1, 0, 12));
    let findings = OsPathJoinRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.os_path_join");
}

#[test]
fn os_path_join_silent_on_pathlib() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "Path", range(1, 1, 0, 4));
    assert!(OsPathJoinRule.run(&fx.ctx()).is_empty());
}

#[test]
fn os_path_join_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_x.py", "python");
    push_call(&mut fx.batch, file, "os.path.join", range(1, 1, 0, 12));
    assert!(OsPathJoinRule.run(&fx.ctx()).is_empty());
}

// ---------- var_for_let -------------------------------------------------

#[test]
fn var_for_let_flags_var_declaration() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.js", "javascript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("x".into()))
            .with_prop("declaration_kind", Value::String("var".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 8))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    let findings = VarForLetRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.var_for_let");
}

#[test]
fn var_for_let_silent_on_let_declaration() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.js", "javascript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("x".into()))
            .with_prop("declaration_kind", Value::String("let".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 8))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(VarForLetRule.run(&fx.ctx()).is_empty());
}

#[test]
fn var_for_let_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/sample.test.js", "javascript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("x".into()))
            .with_prop("declaration_kind", Value::String("var".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 8))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(VarForLetRule.run(&fx.ctx()).is_empty());
}

// ---------- commonjs_require --------------------------------------------

#[test]
fn commonjs_require_flags_require_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.js", "javascript");
    push_call(&mut fx.batch, file, "require", range(1, 1, 0, 7));
    let findings = CommonjsRequireRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.commonjs_require");
}

#[test]
fn commonjs_require_silent_on_import_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.js", "javascript");
    push_call(&mut fx.batch, file, "import", range(1, 1, 0, 6));
    assert!(CommonjsRequireRule.run(&fx.ctx()).is_empty());
}

#[test]
fn commonjs_require_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/sample.js", "javascript");
    push_call(&mut fx.batch, file, "require", range(1, 1, 0, 7));
    assert!(CommonjsRequireRule.run(&fx.ctx()).is_empty());
}

// ---------- callbacks_over_promises -------------------------------------

#[test]
fn callbacks_over_promises_flags_trailing_callback() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadData".into()))
            .with_prop("last_param_name", Value::String("callback".into()))
            .with_prop("return_type", Value::String("void".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    let findings = CallbacksOverPromisesRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.callbacks_over_promises");
}

#[test]
fn callbacks_over_promises_silent_when_returns_promise() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadData".into()))
            .with_prop("last_param_name", Value::String("callback".into()))
            .with_prop("return_type", Value::String("Promise<Data>".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(CallbacksOverPromisesRule.run(&fx.ctx()).is_empty());
}

#[test]
fn callbacks_over_promises_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/sample.test.ts", "typescript");
    let id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("loadData".into()))
            .with_prop("last_param_name", Value::String("callback".into()))
            .with_prop("return_type", Value::String("void".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    assert!(CallbacksOverPromisesRule.run(&fx.ctx()).is_empty());
}

// ---------- deprecated_unwrap -------------------------------------------

#[test]
fn deprecated_unwrap_flags_unwrap_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    push_call(&mut fx.batch, file, ".unwrap()", range(1, 1, 0, 9));
    let findings = DeprecatedUnwrapRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.deprecated_unwrap");
}

#[test]
fn deprecated_unwrap_silent_on_question_mark() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    push_call(&mut fx.batch, file, "result?", range(1, 1, 0, 7));
    assert!(DeprecatedUnwrapRule.run(&fx.ctx()).is_empty());
}

#[test]
fn deprecated_unwrap_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/integration.rs", "rust");
    push_call(&mut fx.batch, file, ".unwrap()", range(1, 1, 0, 9));
    assert!(DeprecatedUnwrapRule.run(&fx.ctx()).is_empty());
}

// ---------- legacy_format_macro -----------------------------------------

#[test]
fn legacy_format_macro_flags_bare_placeholder() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "format!",
            extra_key: "template",
            extra_val: "\"{}\"",
            rng: range(1, 1, 0, 14),
        },
    );
    let findings = LegacyFormatMacroRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.legacy_format_macro");
}

#[test]
fn legacy_format_macro_silent_on_real_template() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "format!",
            extra_key: "template",
            extra_val: "\"x = {x}\"",
            rng: range(1, 1, 0, 14),
        },
    );
    assert!(LegacyFormatMacroRule.run(&fx.ctx()).is_empty());
}

#[test]
fn legacy_format_macro_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/it.rs", "rust");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "format!",
            extra_key: "template",
            extra_val: "\"{}\"",
            rng: range(1, 1, 0, 14),
        },
    );
    assert!(LegacyFormatMacroRule.run(&fx.ctx()).is_empty());
}

// ---------- thread_spawn_no_join ----------------------------------------

#[test]
fn thread_spawn_no_join_flags_dropped_handle() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    // Parent of the call is the File (no Write / Variable binding).
    push_call(&mut fx.batch, file, "thread::spawn", range(1, 1, 0, 14));
    let findings = ThreadSpawnNoJoinRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.thread_spawn_no_join");
}

#[test]
fn thread_spawn_no_join_silent_on_bound_handle() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs", "rust");
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String("h".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, write, file)
        .unwrap();
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String("thread::spawn".into()))
            .with_prop("range", Value::Range(range(1, 1, 8, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, write)
        .unwrap();
    assert!(ThreadSpawnNoJoinRule.run(&fx.ctx()).is_empty());
}

#[test]
fn thread_spawn_no_join_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/it.rs", "rust");
    push_call(&mut fx.batch, file, "thread::spawn", range(1, 1, 0, 14));
    assert!(ThreadSpawnNoJoinRule.run(&fx.ctx()).is_empty());
}

// ---------- sync_in_async_runtime (stub) --------------------------------

#[test]
fn sync_in_async_runtime_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(
        SyncInAsyncRuntimeRule.run(&fx.ctx()).is_empty(),
        "phase-6 stub must not fire until phase-7 wiring lands"
    );
}

// ---------- simplify_boolean_expr (Phase 8) -----------------------------

/// Spec for [`push_function`] — keeps the param count under the
/// Tier-0 ceiling of 5 by grouping the function's name + body
/// metadata into one record.
struct FunctionSpec<'a> {
    parent: NodeId,
    name: &'a str,
    body_key: &'a str,
    body_val: &'a str,
    rng: Range,
}

fn push_function(batch: &mut CpgWriteBatch, spec: FunctionSpec<'_>) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(spec.name.to_owned()))
            .with_prop(spec.body_key, Value::String(spec.body_val.to_owned()))
            .with_prop("range", Value::Range(spec.rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, spec.parent)
        .unwrap();
    id
}

#[test]
fn simplify_boolean_expr_flags_redundant_if_else_python() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_function(
        &mut fx.batch,
        FunctionSpec {
            parent: file,
            name: "is_ok",
            body_key: "body_signature",
            body_val: "if cond: return True\nelse: return False",
            rng: range(1, 4, 0, 50),
        },
    );
    let findings = SimplifyBooleanExprRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.simplify_boolean_expr");
}

#[test]
fn simplify_boolean_expr_flags_brace_form_rust() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/lib.rs", "rust");
    push_function(
        &mut fx.batch,
        FunctionSpec {
            parent: file,
            name: "is_ok",
            body_key: "body_signature",
            body_val: "if cond { return true } else { return false }",
            rng: range(1, 1, 0, 60),
        },
    );
    assert_eq!(SimplifyBooleanExprRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn simplify_boolean_expr_silent_on_real_predicate() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_function(
        &mut fx.batch,
        FunctionSpec {
            parent: file,
            name: "compute",
            body_key: "body_signature",
            body_val: "if cond: return value\nelse: return other",
            rng: range(1, 2, 0, 30),
        },
    );
    assert!(SimplifyBooleanExprRule.run(&fx.ctx()).is_empty());
}

#[test]
fn simplify_boolean_expr_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_x.py", "python");
    push_function(
        &mut fx.batch,
        FunctionSpec {
            parent: file,
            name: "f",
            body_key: "body_signature",
            body_val: "if cond: return True\nelse: return False",
            rng: range(1, 2, 0, 30),
        },
    );
    assert!(SimplifyBooleanExprRule.run(&fx.ctx()).is_empty());
}

// ---------- template_over_concat (Phase 8) ------------------------------

fn push_node_with_text(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    kind: NodeKind,
    text: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(kind)
            .with_prop("text", Value::String(text.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

#[test]
fn template_over_concat_flags_three_operand_concat() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_node_with_text(
        &mut fx.batch,
        file,
        NodeKind::Literal,
        "\"foo \" + x + \" bar\"",
        range(1, 1, 0, 22),
    );
    let findings = TemplateOverConcatRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.template_over_concat");
}

#[test]
fn template_over_concat_silent_on_two_operand_concat() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_node_with_text(
        &mut fx.batch,
        file,
        NodeKind::Literal,
        "\"foo\" + x",
        range(1, 1, 0, 10),
    );
    assert!(TemplateOverConcatRule.run(&fx.ctx()).is_empty());
}

#[test]
fn template_over_concat_silent_without_string_literal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_node_with_text(
        &mut fx.batch,
        file,
        NodeKind::Literal,
        "a + b + c",
        range(1, 1, 0, 9),
    );
    assert!(TemplateOverConcatRule.run(&fx.ctx()).is_empty());
}

// ---------- no_array_for_each (Phase 8) ---------------------------------

#[test]
fn no_array_for_each_flags_for_each_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_call(&mut fx.batch, file, "arr.forEach", range(1, 1, 0, 12));
    let findings = NoArrayForEachRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.no_array_for_each");
}

#[test]
fn no_array_for_each_silent_on_for_of() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_call(&mut fx.batch, file, "arr.map", range(1, 1, 0, 8));
    assert!(NoArrayForEachRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_array_for_each_skips_python() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "arr.forEach", range(1, 1, 0, 12));
    assert!(NoArrayForEachRule.run(&fx.ctx()).is_empty());
}

// ---------- use_pathlib_over_os (Phase 8) -------------------------------

#[test]
fn use_pathlib_over_os_flags_exists() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "os.path.exists", range(1, 1, 0, 14));
    let findings = UsePathlibOverOsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.use_pathlib_over_os");
}

#[test]
fn use_pathlib_over_os_silent_on_join() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "os.path.join", range(1, 1, 0, 12));
    // join is owned by the sibling probe; this one stays silent.
    assert!(UsePathlibOverOsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn use_pathlib_over_os_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_x.py", "python");
    push_call(&mut fx.batch, file, "os.path.isfile", range(1, 1, 0, 14));
    assert!(UsePathlibOverOsRule.run(&fx.ctx()).is_empty());
}

// ---------- bare_reraise_lossy (Phase 8) --------------------------------

fn push_try(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    body_key: &str,
    body_val: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop(body_key, Value::String(body_val.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

#[test]
fn bare_reraise_lossy_flags_missing_from() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_try(
        &mut fx.batch,
        file,
        "body_signature",
        "try: do() except Exception as e: raise CustomError(str(e))",
        range(1, 3, 0, 80),
    );
    let findings = BareReraiseLossyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.bare_reraise_lossy");
}

#[test]
fn bare_reraise_lossy_silent_when_from_clause_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_try(
        &mut fx.batch,
        file,
        "body_signature",
        "try: do() except Exception as e: raise CustomError(str(e)) from e",
        range(1, 3, 0, 90),
    );
    assert!(BareReraiseLossyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_reraise_lossy_silent_on_bare_reraise() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_try(
        &mut fx.batch,
        file,
        "body_signature",
        "try: do() except Exception: raise",
        range(1, 3, 0, 50),
    );
    assert!(BareReraiseLossyRule.run(&fx.ctx()).is_empty());
}

// ---------- dict_literal_over_call (Phase 8) ----------------------------

#[test]
fn dict_literal_over_call_flags_kwargs_only() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "dict",
            extra_key: "args",
            extra_val: "a=1, b=2",
            rng: range(1, 1, 0, 14),
        },
    );
    let findings = DictLiteralOverCallRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.dict_literal_over_call");
}

#[test]
fn dict_literal_over_call_silent_on_positional_seed() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "dict",
            extra_key: "args",
            extra_val: "other, b=2",
            rng: range(1, 1, 0, 14),
        },
    );
    assert!(DictLiteralOverCallRule.run(&fx.ctx()).is_empty());
}

#[test]
fn dict_literal_over_call_skips_other_callees() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "Mapping",
            extra_key: "args",
            extra_val: "a=1",
            rng: range(1, 1, 0, 14),
        },
    );
    assert!(DictLiteralOverCallRule.run(&fx.ctx()).is_empty());
}

// ---------- list_call_in_set_call (Phase 8) -----------------------------

#[test]
fn list_call_in_set_call_flags_set_of_list() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "set",
            extra_key: "signature",
            extra_val: "set(list(x))",
            rng: range(1, 1, 0, 14),
        },
    );
    let findings = ListCallInSetCallRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.list_call_in_set_call");
}

#[test]
fn list_call_in_set_call_silent_on_set_alone() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "set",
            extra_key: "signature",
            extra_val: "set(x)",
            rng: range(1, 1, 0, 8),
        },
    );
    assert!(ListCallInSetCallRule.run(&fx.ctx()).is_empty());
}

#[test]
fn list_call_in_set_call_skips_non_python() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "set",
            extra_key: "signature",
            extra_val: "set(list(x))",
            rng: range(1, 1, 0, 14),
        },
    );
    assert!(ListCallInSetCallRule.run(&fx.ctx()).is_empty());
}

// ---------- string_format_to_fstring (Phase 8) --------------------------

#[test]
fn string_format_to_fstring_flags_dot_format() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "log",
            extra_key: "text",
            extra_val: "\"hello {}\".format(name)",
            rng: range(1, 1, 0, 24),
        },
    );
    let findings = StringFormatToFstringRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.string_format_to_fstring");
}

#[test]
fn string_format_to_fstring_silent_on_fstring() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(
        &mut fx.batch,
        file,
        "print(f\"hello {name}\")",
        range(1, 1, 0, 24),
    );
    assert!(StringFormatToFstringRule.run(&fx.ctx()).is_empty());
}

#[test]
fn string_format_to_fstring_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_x.py", "python");
    push_call_with(
        &mut fx.batch,
        CallWithSpec {
            parent: file,
            callee: "log",
            extra_key: "text",
            extra_val: "\"hi {}\".format(x)",
            rng: range(1, 1, 0, 18),
        },
    );
    assert!(StringFormatToFstringRule.run(&fx.ctx()).is_empty());
}

// ---------- deprecated_unittest_aliases (Phase 8) -----------------------

#[test]
fn deprecated_unittest_aliases_flags_assert_equals() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/test_module.py", "python");
    push_call(&mut fx.batch, file, "self.assertEquals", range(1, 1, 0, 17));
    let findings = DeprecatedUnittestAliasesRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.deprecated_unittest_aliases"
    );
}

#[test]
fn deprecated_unittest_aliases_flags_fail_unless() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "self.failUnless", range(1, 1, 0, 15));
    assert_eq!(DeprecatedUnittestAliasesRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn deprecated_unittest_aliases_silent_on_assert_equal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    push_call(&mut fx.batch, file, "self.assertEqual", range(1, 1, 0, 16));
    assert!(DeprecatedUnittestAliasesRule.run(&fx.ctx()).is_empty());
}

// ---------- consistent_function_scoping (Phase 8) -----------------------

#[test]
fn consistent_function_scoping_flags_independent_inner_fn() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let outer = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("outer".into()))
            .with_prop("param_names", Value::String("a, b".into()))
            .with_prop("range", Value::Range(range(1, 10, 0, 200))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, outer, file)
        .unwrap();
    let inner = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("inner".into()))
            .with_prop("captures", Value::String("0".into()))
            .with_prop("range", Value::Range(range(2, 4, 10, 60))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, inner, outer)
        .unwrap();
    let findings = ConsistentFunctionScopingRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.consistent_function_scoping"
    );
}

#[test]
fn consistent_function_scoping_silent_when_inner_captures_param() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let outer = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("outer".into()))
            .with_prop("param_names", Value::String("a, b".into()))
            .with_prop("range", Value::Range(range(1, 10, 0, 200))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, outer, file)
        .unwrap();
    let inner = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("inner".into()))
            .with_prop("body_signature", Value::String("return a + 1;".into()))
            .with_prop("range", Value::Range(range(2, 4, 10, 60))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, inner, outer)
        .unwrap();
    assert!(ConsistentFunctionScopingRule.run(&fx.ctx()).is_empty());
}

#[test]
fn consistent_function_scoping_silent_for_top_level_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.ts", "typescript");
    let top = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("top".into()))
            .with_prop("captures", Value::String("0".into()))
            .with_prop("range", Value::Range(range(1, 4, 0, 60))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, top, file).unwrap();
    assert!(ConsistentFunctionScopingRule.run(&fx.ctx()).is_empty());
}

// ---------- logging_fstring (Phase 9 — Python) ---------------------------

use crate::banned_import_alias::BannedImportAliasRule;
use crate::collapsible_if::CollapsibleIfRule;
use crate::logging_fstring::LoggingFstringRule;
use crate::try_consider_else::TryConsiderElseRule;
use crate::try_except_pass::TryExceptPassRule;

#[test]
fn logging_fstring_flags_logger_info_fstring() {
    let body = "def f(name):\n    logger.info(f\"hello {name}\")\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    let findings = LoggingFstringRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.logging_fstring");
}

#[test]
fn logging_fstring_silent_on_percent_format() {
    let body = "def f(name):\n    logger.info(\"hello %s\", name)\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    assert!(LoggingFstringRule.run(&fx.ctx()).is_empty());
}

#[test]
fn logging_fstring_silent_on_non_logger_call() {
    let body = "def f(x):\n    print(f\"value {x}\")\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    assert!(LoggingFstringRule.run(&fx.ctx()).is_empty());
}

// ---------- try_consider_else (Phase 9 — Python) -------------------------

#[test]
fn try_consider_else_flags_trailing_use() {
    let body_text = "try:\n    x = call()\n    use(x)\nexcept E:\n    handle()";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    let findings = TryConsiderElseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.try_consider_else");
}

#[test]
fn try_consider_else_silent_on_minimal_try() {
    let body_text = "try:\n    x = call()\nexcept E:\n    handle()";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 4, 0, 60))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    assert!(TryConsiderElseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn try_consider_else_silent_when_tail_is_return() {
    let body_text = "try:\n    x = call()\n    return x\nexcept E:\n    handle()";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    assert!(TryConsiderElseRule.run(&fx.ctx()).is_empty());
}

// ---------- collapsible_if (Phase 9 — Python) ----------------------------

#[test]
fn collapsible_if_flags_simple_nested_if() {
    let body = "def f(a, b):\n    if a:\n        if b:\n            do()\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    let findings = CollapsibleIfRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.collapsible_if");
}

#[test]
fn collapsible_if_silent_when_outer_has_else() {
    let body =
        "def f(a, b):\n    if a:\n        if b:\n            do()\n    else:\n        bail()\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    assert!(CollapsibleIfRule.run(&fx.ctx()).is_empty());
}

#[test]
fn collapsible_if_silent_on_non_if_inner() {
    let body = "def f(a):\n    if a:\n        do()\n        more()\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    assert!(CollapsibleIfRule.run(&fx.ctx()).is_empty());
}

// ---------- banned_import_alias (Phase 9 — Python) -----------------------

#[test]
fn banned_import_alias_flags_numpy_stutter() {
    let body = "import numpy as numpy\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    let findings = BannedImportAliasRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.banned_import_alias");
}

#[test]
fn banned_import_alias_silent_on_canonical_alias() {
    let body = "import numpy as np\nimport pandas as pd\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    assert!(BannedImportAliasRule.run(&fx.ctx()).is_empty());
}

#[test]
fn banned_import_alias_flags_pandas_typo() {
    let body = "import pandas as panda\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sample.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sample.py"),
        body.as_bytes().to_vec(),
    );
    let findings = BannedImportAliasRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].message.headline.contains("pandas"));
}

// ---------- try_except_pass (Phase 9 — Python) ---------------------------

#[test]
fn try_except_pass_flags_silent_pass() {
    let body_text = "try:\n    do()\nexcept Exception:\n    pass";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 4, 0, 60))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    let findings = TryExceptPassRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.try_except_pass");
}

#[test]
fn try_except_pass_silent_when_logger_present() {
    let body_text =
        "try:\n    do()\nexcept Exception as e:\n    logger.warning('ignored: %s', e)\n    pass";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    assert!(TryExceptPassRule.run(&fx.ctx()).is_empty());
}

#[test]
fn try_except_pass_silent_when_explanatory_comment() {
    let body_text =
        "try:\n    do()\nexcept KeyError:\n    # documented: optional cache miss\n    pass";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/sample.py", "python");
    let try_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("body_signature", Value::String(body_text.into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 100))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_id, file)
        .unwrap();
    assert!(TryExceptPassRule.run(&fx.ctx()).is_empty());
}

// ---------- django_url_path_param_required (Phase 10 — DJ001 family) -----

use crate::django_locals_in_render::DjangoLocalsInRenderRule;
use crate::django_url_path_param_required::DjangoUrlPathParamRequiredRule;
use crate::numpy_legacy_random::NumpyLegacyRandomRule;
use crate::pandas_chained_assignment::PandasChainedAssignmentRule;

#[test]
fn django_url_path_flags_untyped_capture() {
    let body = "urlpatterns = [\n    path('orders/<id>/', views.show),\n]\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/urls.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/urls.py"),
        body.as_bytes().to_vec(),
    );
    let findings = DjangoUrlPathParamRequiredRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.django_url_path_param_required"
    );
}

#[test]
fn django_url_path_silent_with_int_converter() {
    let body = "urlpatterns = [\n    path('orders/<int:id>/', views.show),\n]\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/urls.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/urls.py"),
        body.as_bytes().to_vec(),
    );
    assert!(DjangoUrlPathParamRequiredRule.run(&fx.ctx()).is_empty());
}

#[test]
fn django_url_path_silent_on_re_path_with_no_captures() {
    // `re_path` patterns are exempt when no `<...>` captures appear.
    let body = "urlpatterns = [\n    re_path(r'^orders/$', views.list),\n]\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/urls.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/urls.py"),
        body.as_bytes().to_vec(),
    );
    assert!(DjangoUrlPathParamRequiredRule.run(&fx.ctx()).is_empty());
}

// ---------- django_locals_in_render (Phase 10 — ruff DJ012) --------------

#[test]
fn django_locals_flags_render_with_locals() {
    let body = "def view(request):\n    user = request.user\n    return render(request, 'tpl.html', locals())\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/views.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/views.py"),
        body.as_bytes().to_vec(),
    );
    let findings = DjangoLocalsInRenderRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.django_locals_in_render");
}

#[test]
fn django_locals_silent_with_explicit_dict() {
    let body = "def view(request):\n    user = request.user\n    return render(request, 'tpl.html', {'user': user})\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/views.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/views.py"),
        body.as_bytes().to_vec(),
    );
    assert!(DjangoLocalsInRenderRule.run(&fx.ctx()).is_empty());
}

#[test]
fn django_locals_silent_when_locals_used_outside_render() {
    let body = "def view(request):\n    debug = locals()\n    return debug\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/views.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/views.py"),
        body.as_bytes().to_vec(),
    );
    assert!(DjangoLocalsInRenderRule.run(&fx.ctx()).is_empty());
}

// ---------- numpy_legacy_random (Phase 10 — ruff NPY002) -----------------

#[test]
fn numpy_legacy_random_flags_np_random_rand() {
    let body = "def sample(n):\n    return np.random.rand(n)\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sim.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sim.py"),
        body.as_bytes().to_vec(),
    );
    let findings = NumpyLegacyRandomRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.numpy_legacy_random");
}

#[test]
fn numpy_legacy_random_silent_on_default_rng() {
    let body = "def sample(n):\n    rng = np.random.default_rng(42)\n    return rng.random(n)\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sim.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sim.py"),
        body.as_bytes().to_vec(),
    );
    assert!(NumpyLegacyRandomRule.run(&fx.ctx()).is_empty());
}

#[test]
fn numpy_legacy_random_flags_seed() {
    let body = "import numpy as np\nnp.random.seed(0)\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/sim.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/sim.py"),
        body.as_bytes().to_vec(),
    );
    let findings = NumpyLegacyRandomRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].message.headline.contains("seed"));
}

// ---------- pandas_chained_assignment (Phase 10 — ruff PD901) ------------

#[test]
fn pandas_chained_assignment_flags_chained_subscript() {
    let body = "def patch(df):\n    df['col'][0] = 1\n    return df\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/patch.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/patch.py"),
        body.as_bytes().to_vec(),
    );
    let findings = PandasChainedAssignmentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.pandas_chained_assignment"
    );
}

#[test]
fn pandas_chained_assignment_silent_on_loc() {
    let body = "def patch(df):\n    df.loc[0, 'col'] = 1\n    return df\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/patch.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/patch.py"),
        body.as_bytes().to_vec(),
    );
    assert!(PandasChainedAssignmentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pandas_chained_assignment_silent_on_single_subscript_eq() {
    let body = "def patch(df):\n    df['col'] = 1\n    return df\n";
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, "src/patch.py", "python");
    fx.source.insert(
        camino::Utf8PathBuf::from("src/patch.py"),
        body.as_bytes().to_vec(),
    );
    assert!(PandasChainedAssignmentRule.run(&fx.ctx()).is_empty());
}

// ---------- manual_let_else (Phase 10 — clippy) -------------------------

use crate::manual_let_else::ManualLetElseRule;
use crate::redundant_closure::RedundantClosureRule;
use crate::unnecessary_lazy_evaluations::UnnecessaryLazyEvaluationsRule;

#[test]
fn manual_let_else_flags_some_v_v_with_return_none_arm() {
    let body = "fn lookup(id: u32) -> Result<User, Err> {\n    \
                    let user = match find_user(id) {\n        \
                        Some(u) => u,\n        \
                        None => return Err(Err::Missing),\n    \
                    };\n    \
                    Ok(user)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = ManualLetElseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.manual_let_else");
}

#[test]
fn manual_let_else_silent_when_none_arm_continues_normally() {
    let body = "fn lookup(id: u32) -> u32 {\n    \
                    let user = match find_user(id) {\n        \
                        Some(u) => u,\n        \
                        None => default_user(),\n    \
                    };\n    \
                    user.id\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(ManualLetElseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn manual_let_else_silent_on_unrelated_match() {
    let body = "fn classify(x: i32) -> &'static str {\n    \
                    match x {\n        \
                        0 => \"zero\",\n        \
                        _ => \"other\",\n    \
                    }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(ManualLetElseRule.run(&fx.ctx()).is_empty());
}

// ---------- redundant_closure (Phase 10 — clippy) -----------------------

#[test]
fn redundant_closure_flags_pipe_to_single_arg_fn() {
    let body = "fn double_all(xs: &[u32]) -> Vec<u32> {\n    \
                    xs.iter().map(|x| double(x)).collect()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = RedundantClosureRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.modernize.redundant_closure");
}

#[test]
fn redundant_closure_silent_on_real_work_in_body() {
    let body = "fn process(xs: &[u32]) -> Vec<u32> {\n    \
                    xs.iter().map(|x| x + 1).collect()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(RedundantClosureRule.run(&fx.ctx()).is_empty());
}

#[test]
fn redundant_closure_silent_when_arg_renamed_in_body() {
    let body = "fn process(xs: &[u32]) -> Vec<u32> {\n    \
                    xs.iter().map(|x| double(y)).collect()\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(RedundantClosureRule.run(&fx.ctx()).is_empty());
}

// ---------- unnecessary_lazy_evaluations (Phase 10 — clippy) ------------

#[test]
fn unnecessary_lazy_evaluations_flags_unwrap_or_else_with_int_lit() {
    let body = "fn timeout(cfg: Option<u32>) -> u32 {\n    \
                    cfg.unwrap_or_else(|| 30)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    let findings = UnnecessaryLazyEvaluationsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.unnecessary_lazy_evaluations"
    );
}

#[test]
fn unnecessary_lazy_evaluations_silent_on_real_computation() {
    let body = "fn timeout(cfg: Option<u32>) -> u32 {\n    \
                    cfg.unwrap_or_else(|| compute_default())\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert!(UnnecessaryLazyEvaluationsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unnecessary_lazy_evaluations_flags_or_else_with_string_lit() {
    let body = "fn lookup(c: Option<&str>) -> Option<&str> {\n    \
                    c.or_else(|| Some(\"fallback\"))\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs", "rust");
    assert_eq!(UnnecessaryLazyEvaluationsRule.run(&fx.ctx()).len(), 1);
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_thirty_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinModernizePack)
        .expect("Family-26 pack registers without error");
    assert_eq!(reg.rules().count(), 35);
    for slug in [
        // Phase 6.
        "cc.modernize.string_format_legacy",
        "cc.modernize.deprecated_typing_alias",
        "cc.modernize.os_path_join",
        "cc.modernize.var_for_let",
        "cc.modernize.commonjs_require",
        "cc.modernize.callbacks_over_promises",
        "cc.modernize.deprecated_unwrap",
        "cc.modernize.legacy_format_macro",
        "cc.modernize.thread_spawn_no_join",
        "cc.modernize.sync_in_async_runtime",
        // Phase 8.
        "cc.modernize.simplify_boolean_expr",
        "cc.modernize.template_over_concat",
        "cc.modernize.no_array_for_each",
        "cc.modernize.use_pathlib_over_os",
        "cc.modernize.bare_reraise_lossy",
        "cc.modernize.dict_literal_over_call",
        "cc.modernize.list_call_in_set_call",
        "cc.modernize.string_format_to_fstring",
        "cc.modernize.deprecated_unittest_aliases",
        "cc.modernize.consistent_function_scoping",
        // Phase 9 (Python).
        "cc.modernize.logging_fstring",
        "cc.modernize.try_consider_else",
        "cc.modernize.collapsible_if",
        "cc.modernize.banned_import_alias",
        "cc.modernize.try_except_pass",
        // Phase 10 (Python long-tail — Django/NumPy/pandas).
        "cc.modernize.django_url_path_param_required",
        "cc.modernize.django_locals_in_render",
        "cc.modernize.numpy_legacy_random",
        "cc.modernize.pandas_chained_assignment",
        // Phase 10 (Rust long-tail — clippy).
        "cc.modernize.manual_let_else",
        "cc.modernize.redundant_closure",
        "cc.modernize.unnecessary_lazy_evaluations",
        // Phase 12 (final OSS long-tail sweep — Python modernization trio).
        "cc.modernize.python_walrus_for_assign_in_cond",
        "cc.modernize.python_match_case_for_chain",
        "cc.modernize.python_dataclass_for_class_with_init",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

// ---------- python_walrus_for_assign_in_cond (Phase 12) -----------------

#[test]
fn walrus_for_assign_flags_assign_then_if_no_body_use() {
    use crate::python_walrus_for_assign_in_cond::PythonWalrusForAssignInCondRule;
    let body = "def f():\n    \
                    x = compute()\n    \
                    if x > 0:\n        \
                        log(\"ok\")\n";
    let mut fx = Fixture::new().with_source("src/svc.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.py", "python");
    let findings = PythonWalrusForAssignInCondRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.python_walrus_for_assign_in_cond"
    );
}

#[test]
fn walrus_for_assign_silent_when_x_used_in_body() {
    use crate::python_walrus_for_assign_in_cond::PythonWalrusForAssignInCondRule;
    let body = "def f():\n    \
                    x = compute()\n    \
                    if x > 0:\n        \
                        log(x)\n";
    let mut fx = Fixture::new().with_source("src/svc.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.py", "python");
    assert!(PythonWalrusForAssignInCondRule.run(&fx.ctx()).is_empty());
}

#[test]
fn walrus_for_assign_silent_on_non_call_rhs() {
    use crate::python_walrus_for_assign_in_cond::PythonWalrusForAssignInCondRule;
    let body = "def f():\n    \
                    x = 5\n    \
                    if x > 0:\n        \
                        log(\"ok\")\n";
    let mut fx = Fixture::new().with_source("src/svc.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.py", "python");
    assert!(PythonWalrusForAssignInCondRule.run(&fx.ctx()).is_empty());
}

// ---------- python_match_case_for_chain (Phase 12) ----------------------

#[test]
fn match_case_for_chain_flags_three_arm_chain() {
    use crate::python_match_case_for_chain::PythonMatchCaseForChainRule;
    let body = "def dispatch(s):\n    \
                    if s == \"open\":\n        \
                        h_open()\n    \
                    elif s == \"closed\":\n        \
                        h_closed()\n    \
                    elif s == \"pending\":\n        \
                        h_pending()\n";
    let mut fx = Fixture::new().with_source("src/dispatch.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/dispatch.py", "python");
    let findings = PythonMatchCaseForChainRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.python_match_case_for_chain"
    );
}

#[test]
fn match_case_for_chain_silent_on_two_arm_chain() {
    use crate::python_match_case_for_chain::PythonMatchCaseForChainRule;
    let body = "def f(s):\n    \
                    if s == \"open\":\n        \
                        h_open()\n    \
                    elif s == \"closed\":\n        \
                        h_closed()\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    assert!(PythonMatchCaseForChainRule.run(&fx.ctx()).is_empty());
}

#[test]
fn match_case_for_chain_silent_on_different_variables() {
    use crate::python_match_case_for_chain::PythonMatchCaseForChainRule;
    let body = "def f(a, b, c):\n    \
                    if a == 1:\n        \
                        x()\n    \
                    elif b == 2:\n        \
                        y()\n    \
                    elif c == 3:\n        \
                        z()\n";
    let mut fx = Fixture::new().with_source("src/x.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/x.py", "python");
    assert!(PythonMatchCaseForChainRule.run(&fx.ctx()).is_empty());
}

// ---------- python_dataclass_for_class_with_init (Phase 12) -------------

#[test]
fn dataclass_flags_pure_assign_init() {
    use crate::python_dataclass_for_class_with_init::PythonDataclassForClassWithInitRule;
    let body = "class User:\n    \
                    def __init__(self, name, age, email):\n        \
                        self.name = name\n        \
                        self.age = age\n        \
                        self.email = email\n";
    let mut fx = Fixture::new().with_source("src/user.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/user.py", "python");
    let findings = PythonDataclassForClassWithInitRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.modernize.python_dataclass_for_class_with_init"
    );
}

#[test]
fn dataclass_silent_on_decorated_class() {
    use crate::python_dataclass_for_class_with_init::PythonDataclassForClassWithInitRule;
    let body = "@dataclass\n\
                class User:\n    \
                    name: str\n    \
                    age: int\n";
    let mut fx = Fixture::new().with_source("src/user.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/user.py", "python");
    assert!(PythonDataclassForClassWithInitRule
        .run(&fx.ctx())
        .is_empty());
}

#[test]
fn dataclass_silent_on_init_with_validation() {
    use crate::python_dataclass_for_class_with_init::PythonDataclassForClassWithInitRule;
    let body = "class User:\n    \
                    def __init__(self, name, age):\n        \
                        if age < 0:\n            \
                            raise ValueError\n        \
                        self.name = name\n        \
                        self.age = age\n";
    let mut fx = Fixture::new().with_source("src/user.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/user.py", "python");
    // The init body has a non-pure-assign line — must not fire.
    assert!(PythonDataclassForClassWithInitRule
        .run(&fx.ctx())
        .is_empty());
}
