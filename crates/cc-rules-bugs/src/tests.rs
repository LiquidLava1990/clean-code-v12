//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive (violating) and one negative
//! (clean) case. The pack-level test confirms all seven rules register
//! and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::float_money::FloatMoneyRule;
use crate::locale_dependent::LocaleDependentRule;
use crate::null_propagation::NullPropagationRule;
use crate::off_by_one::OffByOneRule;
use crate::state_machine::StateMachineRule;
use crate::time_bomb::TimeBombRule;
use crate::type_confusion::TypeConfusionRule;
use crate::BuiltinBugsPack;

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

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee_ref: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

// ---------- null_propagation --------------------------------------------

#[test]
fn null_propagation_flags_dict_get() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(
        &mut fx.batch,
        file,
        "value",
        "config.get(\"key\")",
        range(1, 1, 0, 25),
    );
    let findings = NullPropagationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.null_propagation");
}

#[test]
fn null_propagation_silent_when_unwrap_or_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(
        &mut fx.batch,
        file,
        "value",
        "config.get(\"key\").unwrap_or(\"default\")",
        range(1, 1, 0, 40),
    );
    assert!(NullPropagationRule.run(&fx.ctx()).is_empty());
}

// ---------- off_by_one --------------------------------------------------

#[test]
fn off_by_one_flags_i_plus_one_indexing() {
    let body = "for i in range(len(xs)):\n    print(xs[i+1])\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for i in range(len(xs))".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    let findings = OffByOneRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.off_by_one");
}

#[test]
fn off_by_one_silent_on_clean_loop() {
    let body = "for i in range(len(xs)):\n    print(xs[i])\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for i in range(len(xs))".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    assert!(OffByOneRule.run(&fx.ctx()).is_empty());
}

// ---------- type_confusion ----------------------------------------------

#[test]
fn type_confusion_flags_any_into_typed_binding() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("load_blob".into()))
            .with_prop("return_type", Value::String("Any".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 10))),
    );
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String("user".into()))
            .with_prop("target_type", Value::String("User".into()))
            .with_prop("initializer", Value::String("load_blob()".into()))
            .with_prop("range", Value::Range(range(2, 2, 11, 25))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, write, file)
        .unwrap();
    let findings = TypeConfusionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.type_confusion");
}

#[test]
fn type_confusion_silent_when_typed_returner() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("load_user".into()))
            .with_prop("return_type", Value::String("User".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 10))),
    );
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String("user".into()))
            .with_prop("target_type", Value::String("User".into()))
            .with_prop("initializer", Value::String("load_user()".into()))
            .with_prop("range", Value::Range(range(2, 2, 11, 25))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, write, file)
        .unwrap();
    assert!(TypeConfusionRule.run(&fx.ctx()).is_empty());
}

// ---------- state_machine -----------------------------------------------

#[test]
fn state_machine_flags_use_after_close() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(
        &mut fx.batch,
        file,
        "fh",
        "open(\"x.txt\")",
        range(1, 1, 0, 20),
    );
    let close = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("receiver", Value::String("fh".into()))
            .with_prop("method", Value::String("close".into()))
            .with_prop("range", Value::Range(range(2, 2, 21, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, close, file)
        .unwrap();
    let read = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("receiver", Value::String("fh".into()))
            .with_prop("method", Value::String("read".into()))
            .with_prop("range", Value::Range(range(3, 3, 31, 40))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, read, file)
        .unwrap();
    let findings = StateMachineRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.state_machine");
}

#[test]
fn state_machine_silent_when_no_post_close_use() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_write(
        &mut fx.batch,
        file,
        "fh",
        "open(\"x.txt\")",
        range(1, 1, 0, 20),
    );
    let read = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("receiver", Value::String("fh".into()))
            .with_prop("method", Value::String("read".into()))
            .with_prop("range", Value::Range(range(2, 2, 21, 30))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, read, file)
        .unwrap();
    let close = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("receiver", Value::String("fh".into()))
            .with_prop("method", Value::String("close".into()))
            .with_prop("range", Value::Range(range(3, 3, 31, 40))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, close, file)
        .unwrap();
    assert!(StateMachineRule.run(&fx.ctx()).is_empty());
}

// ---------- time_bomb ---------------------------------------------------

#[test]
fn time_bomb_flags_iso_date_literal() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String("2026-12-31".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 10))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    let findings = TimeBombRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.time_bomb");
}

#[test]
fn time_bomb_silent_on_non_date_string() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let lit = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String("hello world".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 11))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, lit, file).unwrap();
    assert!(TimeBombRule.run(&fx.ctx()).is_empty());
}

#[test]
fn time_bomb_flags_utcnow_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "datetime.utcnow", range(1, 1, 0, 17));
    let findings = TimeBombRule.run(&fx.ctx());
    assert!(findings
        .iter()
        .any(|f| f.message.headline.contains("utcnow")));
}

// ---------- float_money -------------------------------------------------

#[test]
fn float_money_flags_total_amount_float() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("total_amount".into()))
            .with_prop("type", Value::String("float".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    let findings = FloatMoneyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.float_money");
}

#[test]
fn float_money_silent_on_decimal_money() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let var = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("total_amount".into()))
            .with_prop("type", Value::String("Decimal".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 20))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, var, file).unwrap();
    assert!(FloatMoneyRule.run(&fx.ctx()).is_empty());
}

// ---------- locale_dependent --------------------------------------------

#[test]
fn locale_dependent_flags_str_upper() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "name.upper(", range(1, 1, 0, 11));
    let findings = LocaleDependentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.locale_dependent");
}

#[test]
fn locale_dependent_silent_on_non_case_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "name.strip", range(1, 1, 0, 10));
    assert!(LocaleDependentRule.run(&fx.ctx()).is_empty());
}

// ---------- equals_hashcode_pair (Phase 7) ------------------------------

use crate::cmp_to_nan::CmpToNanRule;
use crate::deferred_close_no_err::DeferredCloseNoErrRule;
use crate::equals_hashcode_pair::EqualsHashcodePairRule;
use crate::format_string_drift::FormatStringDriftRule;
use crate::identity_binary_expr::IdentityBinaryExprRule;
use crate::mutate_during_iteration::MutateDuringIterationRule;
use crate::regex_invalid::RegexInvalidRule;
use crate::shift_amount_oor::ShiftAmountOorRule;

fn push_class(batch: &mut CpgWriteBatch, parent: NodeId, name: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range(1, 50, 0, 200))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_method(batch: &mut CpgWriteBatch, parent: NodeId, name: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Method)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range(1, 5, 0, 30))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

#[test]
fn equals_hashcode_pair_flags_eq_without_hash() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let class = push_class(&mut fx.batch, file, "Money");
    let _ = push_method(&mut fx.batch, class, "__eq__");
    let findings = EqualsHashcodePairRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.equals_hashcode_pair");
    assert!(findings[0].message.headline.contains("__eq__"));
}

#[test]
fn equals_hashcode_pair_silent_when_both_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let class = push_class(&mut fx.batch, file, "Money");
    let _ = push_method(&mut fx.batch, class, "__eq__");
    let _ = push_method(&mut fx.batch, class, "__hash__");
    assert!(EqualsHashcodePairRule.run(&fx.ctx()).is_empty());
}

#[test]
fn equals_hashcode_pair_flags_ts_equals_without_hashcode() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/widget.ts");
    let class = push_class(&mut fx.batch, file, "Widget");
    let _ = push_method(&mut fx.batch, class, "equals");
    let findings = EqualsHashcodePairRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.headline.contains("equals"));
}

// ---------- identity_binary_expr (Phase 7) -------------------------------

#[test]
fn identity_binary_expr_flags_x_eq_x() {
    let body = "let stale = price == price;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    let findings = IdentityBinaryExprRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.identity_binary_expr");
}

#[test]
fn identity_binary_expr_silent_on_distinct_operands() {
    let body = "let total = price * qty;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    assert!(IdentityBinaryExprRule.run(&fx.ctx()).is_empty());
}

#[test]
fn identity_binary_expr_silent_on_comments() {
    let body = "// note: x == x is a tautology\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    assert!(IdentityBinaryExprRule.run(&fx.ctx()).is_empty());
}

// ---------- cmp_to_nan (Phase 7) -----------------------------------------

#[test]
fn cmp_to_nan_flags_python_float_nan_eq() {
    let body = "if x == float(\"nan\"):\n    pass\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = CmpToNanRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.cmp_to_nan");
}

#[test]
fn cmp_to_nan_flags_js_strict_eq() {
    let body = "if (x === Number.NaN) return;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    let findings = CmpToNanRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn cmp_to_nan_silent_on_isnan_call() {
    let body = "if math.isnan(x):\n    pass\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(CmpToNanRule.run(&fx.ctx()).is_empty());
}

// ---------- shift_amount_oor (Phase 7) -----------------------------------

#[test]
fn shift_amount_oor_flags_shift_by_32() {
    let body = "let mask = value << 32;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    let findings = ShiftAmountOorRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.shift_amount_oor");
}

#[test]
fn shift_amount_oor_silent_on_safe_shift() {
    let body = "let mask = value << 8;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    assert!(ShiftAmountOorRule.run(&fx.ctx()).is_empty());
}

#[test]
fn shift_amount_oor_flags_right_shift_by_64() {
    let body = "let high = value >> 64;\n";
    let mut fx = Fixture::new().with_source("src/widget.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/widget.ts");
    let findings = ShiftAmountOorRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

// ---------- format_string_drift (Phase 7) --------------------------------

fn push_call_with_args(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee: &str,
    arg_count: u64,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop("arg_count", Value::Uint(arg_count))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_literal_child(batch: &mut CpgWriteBatch, parent: NodeId, value: &str, rng: Range) {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String(value.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
}

#[test]
fn format_string_drift_flags_too_few_args() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.go");
    let call = push_call_with_args(
        &mut fx.batch,
        file,
        "fmt.Sprintf",
        2, // format + 1 arg, but format has 2 placeholders
        range(1, 1, 0, 30),
    );
    push_literal_child(&mut fx.batch, call, "%s -> %d", range(1, 1, 12, 22));
    let findings = FormatStringDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.format_string_drift");
}

#[test]
fn format_string_drift_silent_when_counts_match() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.go");
    let call = push_call_with_args(
        &mut fx.batch,
        file,
        "fmt.Sprintf",
        3, // format + 2 args
        range(1, 1, 0, 30),
    );
    push_literal_child(&mut fx.batch, call, "%s -> %d", range(1, 1, 12, 22));
    assert!(FormatStringDriftRule.run(&fx.ctx()).is_empty());
}

#[test]
fn format_string_drift_flags_rust_too_many_braces() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/main.rs");
    let call = push_call_with_args(
        &mut fx.batch,
        file,
        "format!",
        2, // format + 1 arg, but {} {} is 2 placeholders
        range(1, 1, 0, 30),
    );
    push_literal_child(&mut fx.batch, call, "{} -> {}", range(1, 1, 8, 18));
    let findings = FormatStringDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- regex_invalid (Phase 7) --------------------------------------

#[test]
fn regex_invalid_flags_unbalanced_bracket() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = push_call(&mut fx.batch, file, "re.compile", range(1, 1, 0, 30));
    push_literal_child(&mut fx.batch, call, "[unclosed", range(1, 1, 11, 22));
    let findings = RegexInvalidRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.regex_invalid");
}

#[test]
fn regex_invalid_silent_on_valid_pattern() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = push_call(&mut fx.batch, file, "re.compile", range(1, 1, 0, 30));
    push_literal_child(&mut fx.batch, call, "[a-z]+\\d{2,4}", range(1, 1, 11, 24));
    assert!(RegexInvalidRule.run(&fx.ctx()).is_empty());
}

#[test]
fn regex_invalid_flags_dangling_backslash() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = push_call(&mut fx.batch, file, "regex::Regex::new", range(1, 1, 0, 40));
    push_literal_child(&mut fx.batch, call, "foo\\", range(1, 1, 18, 24));
    let findings = RegexInvalidRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

// ---------- deferred_close_no_err (Phase 7) ------------------------------

#[test]
fn deferred_close_no_err_flags_defer_file_close() {
    let body = "package main\nfunc f() {\n    defer file.Close()\n}\n";
    let mut fx = Fixture::new().with_source("src/foo.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.go");
    let findings = DeferredCloseNoErrRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.deferred_close_no_err");
}

#[test]
fn deferred_close_no_err_silent_in_test_files() {
    let body = "package main\nfunc f() {\n    defer file.Close()\n}\n";
    let mut fx = Fixture::new().with_source("src/foo_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo_test.go");
    assert!(DeferredCloseNoErrRule.run(&fx.ctx()).is_empty());
}

#[test]
fn deferred_close_no_err_silent_for_non_go() {
    let body = "def f():\n    defer = something.Close()\n";
    let mut fx = Fixture::new().with_source("src/foo.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.py");
    assert!(DeferredCloseNoErrRule.run(&fx.ctx()).is_empty());
}

// ---------- mutate_during_iteration (Phase 7) ----------------------------

#[test]
fn mutate_during_iteration_flags_append_inside_for() {
    let body = "for x in items:\n    items.append(x * 2)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for x in items:".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    let findings = MutateDuringIterationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.mutate_during_iteration");
}

#[test]
fn mutate_during_iteration_silent_on_clean_iteration() {
    let body = "for x in items:\n    print(x)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for x in items:".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    assert!(MutateDuringIterationRule.run(&fx.ctx()).is_empty());
}

// ---------- tick_leak (Phase 8) ------------------------------------------

use crate::always_throws::AlwaysThrowsRule;
use crate::dead_thread::DeadThreadRule;
use crate::html_url_javascript::HtmlUrlJavascriptRule;
use crate::tick_leak::TickLeakRule;
use crate::use_after_move::UseAfterMoveRule;

#[test]
fn tick_leak_flags_call_in_helper_fn() {
    let body = "package svc\n\
                func startWorker() {\n    \
                    ch := time.Tick(time.Second)\n    \
                    _ = ch\n}\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = TickLeakRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.tick_leak");
}

#[test]
fn tick_leak_silent_when_call_is_inside_main() {
    let body = "package main\n\
                func main() {\n    \
                    ch := time.Tick(time.Second)\n    \
                    _ = ch\n}\n";
    let mut fx = Fixture::new().with_source("src/main.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/main.go");
    assert!(TickLeakRule.run(&fx.ctx()).is_empty());
}

#[test]
fn tick_leak_silent_for_non_go_files() {
    let body = "ch = time.Tick(1)\n";
    let mut fx = Fixture::new().with_source("src/foo.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.py");
    assert!(TickLeakRule.run(&fx.ctx()).is_empty());
}

// ---------- dead_thread (Phase 8) ----------------------------------------

#[test]
fn dead_thread_flags_unstarted_thread() {
    let body = "class Worker {\n    \
                    void run() {\n        \
                        Thread t = new Thread(this::doIt);\n        \
                        log.info(\"created\");\n    \
                    }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/Worker.java", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/Worker.java");
    let findings = DeadThreadRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.dead_thread");
}

#[test]
fn dead_thread_silent_when_started() {
    let body = "class Worker {\n    \
                    void run() {\n        \
                        Thread t = new Thread(this::doIt);\n        \
                        t.start();\n    \
                    }\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/Worker.java", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/Worker.java");
    assert!(DeadThreadRule.run(&fx.ctx()).is_empty());
}

#[test]
fn dead_thread_silent_for_non_java_files() {
    let body = "Thread t = new Thread(r);\n";
    let mut fx = Fixture::new().with_source("src/foo.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.py");
    assert!(DeadThreadRule.run(&fx.ctx()).is_empty());
}

// ---------- always_throws (Phase 8) --------------------------------------

#[test]
fn always_throws_flags_division_by_literal_zero() {
    let body = "def f(x):\n    return x / 0\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = AlwaysThrowsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.always_throws");
}

#[test]
fn always_throws_silent_on_nonzero_divisor() {
    let body = "def f(x):\n    return x / 2\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(AlwaysThrowsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn always_throws_silent_on_float_zero_prefix() {
    // `x / 0.5` must NOT fire — 0 is a prefix of 0.5, not a complete literal.
    let body = "def f(x):\n    return x / 0.5\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(AlwaysThrowsRule.run(&fx.ctx()).is_empty());
}

// ---------- use_after_move (Phase 8) -------------------------------------

#[test]
fn use_after_move_flags_drop_then_use() {
    let body = "fn f(name: String) {\n    \
                    drop(name);\n    \
                    println!(\"{}\", name);\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = UseAfterMoveRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.use_after_move");
}

#[test]
fn use_after_move_silent_when_rebound() {
    let body = "fn f(name: String) {\n    \
                    drop(name);\n    \
                    let name = String::new();\n    \
                    println!(\"{}\", name);\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(UseAfterMoveRule.run(&fx.ctx()).is_empty());
}

#[test]
fn use_after_move_silent_for_non_rust_files() {
    let body = "drop(name)\nprint(name)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(UseAfterMoveRule.run(&fx.ctx()).is_empty());
}

// ---------- html_url_javascript (Phase 8) --------------------------------

#[test]
fn html_url_javascript_flags_anchor_href() {
    let body = "<a href=\"javascript:alert(1)\">click</a>\n";
    let mut fx = Fixture::new().with_source("src/index.html", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/index.html");
    let findings = HtmlUrlJavascriptRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.html_url_javascript");
}

#[test]
fn html_url_javascript_silent_on_https_href() {
    let body = "<a href=\"https://example.com\">click</a>\n";
    let mut fx = Fixture::new().with_source("src/index.html", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/index.html");
    assert!(HtmlUrlJavascriptRule.run(&fx.ctx()).is_empty());
}

#[test]
fn html_url_javascript_flags_jsx_form_action() {
    let body = "<form formaction='javascript:steal()'>x</form>\n";
    let mut fx = Fixture::new().with_source("src/Foo.tsx", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/Foo.tsx");
    let findings = HtmlUrlJavascriptRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

// ---------- body_close_missing (Phase 9 — Go) ----------------------------

use crate::body_close_missing::BodyCloseMissingRule;
use crate::err_named_inconsistently::ErrNamedInconsistentlyRule;
use crate::errcheck_json::ErrcheckJsonRule;
use crate::nilerr::NilerrRule;

#[test]
fn body_close_missing_flags_unclosed_http_get() {
    let body = "package main\n\
                import \"net/http\"\n\
                func fetch(url string) error {\n    \
                    resp, err := http.Get(url)\n    \
                    if err != nil { return err }\n    \
                    _ = resp\n    \
                    return nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = BodyCloseMissingRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.body_close_missing");
}

#[test]
fn body_close_missing_silent_when_defer_close_present() {
    let body = "package main\n\
                import \"net/http\"\n\
                func fetch(url string) error {\n    \
                    resp, err := http.Get(url)\n    \
                    if err != nil { return err }\n    \
                    defer resp.Body.Close()\n    \
                    return nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(BodyCloseMissingRule.run(&fx.ctx()).is_empty());
}

#[test]
fn body_close_missing_silent_in_test_files() {
    let body = "package main\n\
                func f() {\n    \
                    resp, _ := http.Get(\"x\")\n    \
                    _ = resp\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc_test.go");
    assert!(BodyCloseMissingRule.run(&fx.ctx()).is_empty());
}

// ---------- errcheck_json (Phase 9 — Go) ---------------------------------

#[test]
fn errcheck_json_flags_underscore_discard() {
    let body = "package main\n\
                func f(v Foo) []byte {\n    \
                    b, _ := json.Marshal(v)\n    \
                    return b\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = ErrcheckJsonRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.errcheck_json");
}

#[test]
fn errcheck_json_silent_when_error_captured() {
    let body = "package main\n\
                func f(v Foo) ([]byte, error) {\n    \
                    b, err := json.Marshal(v)\n    \
                    if err != nil { return nil, err }\n    \
                    return b, nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(ErrcheckJsonRule.run(&fx.ctx()).is_empty());
}

#[test]
fn errcheck_json_silent_for_non_go() {
    let body = "json.Marshal(v)\n";
    let mut fx = Fixture::new().with_source("src/foo.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/foo.py");
    assert!(ErrcheckJsonRule.run(&fx.ctx()).is_empty());
}

// ---------- err_named_inconsistently (Phase 9 — Go) ----------------------

#[test]
fn err_named_inconsistently_flags_some_error_suffix() {
    let body = "package main\n\
                import \"errors\"\n\
                var SomeError = errors.New(\"boom\")\n";
    let mut fx = Fixture::new().with_source("src/sentinel.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/sentinel.go");
    let findings = ErrNamedInconsistentlyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.err_named_inconsistently");
    assert!(findings[0].message.headline.contains("ErrSome"));
}

#[test]
fn err_named_inconsistently_silent_on_canonical_name() {
    let body = "package main\n\
                import \"errors\"\n\
                var ErrNotFound = errors.New(\"missing\")\n\
                var errInternal = errors.New(\"internal\")\n";
    let mut fx = Fixture::new().with_source("src/sentinel.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/sentinel.go");
    assert!(ErrNamedInconsistentlyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn err_named_inconsistently_silent_for_non_error_var() {
    // Plain var declarations whose RHS is not `errors.New` / `fmt.Errorf`
    // are not error sentinels and must not fire.
    let body = "package main\n\
                var DefaultPort = 8080\n";
    let mut fx = Fixture::new().with_source("src/conf.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/conf.go");
    assert!(ErrNamedInconsistentlyRule.run(&fx.ctx()).is_empty());
}

// ---------- nilerr (Phase 9 — Go) ----------------------------------------

#[test]
fn nilerr_flags_swallowed_error() {
    let body = "package main\n\
                func f() error {\n    \
                    err := doThing()\n    \
                    if err != nil {\n        \
                        return nil\n    \
                    }\n    \
                    return nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = NilerrRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.nilerr");
}

#[test]
fn nilerr_silent_when_error_propagated() {
    let body = "package main\n\
                func f() error {\n    \
                    err := doThing()\n    \
                    if err != nil {\n        \
                        return err\n    \
                    }\n    \
                    return nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(NilerrRule.run(&fx.ctx()).is_empty());
}

#[test]
fn nilerr_silent_in_test_files() {
    let body = "package main\n\
                func f() error {\n    \
                    if err != nil {\n        \
                        return nil\n    \
                    }\n    \
                    return nil\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc_test.go");
    assert!(NilerrRule.run(&fx.ctx()).is_empty());
}

// ---------- mutable_arg_default (Phase 9 — Python) -----------------------

use crate::assert_with_tuple::AssertWithTupleRule;
use crate::broad_pytest_raises::BroadPytestRaisesRule;
use crate::fn_call_in_default_arg::FnCallInDefaultArgRule;
use crate::mutable_arg_default::MutableArgDefaultRule;
use crate::unused_loop_variable::UnusedLoopVariableRule;

#[test]
fn mutable_arg_default_flags_list_default() {
    let body = "def f(items=[]):\n    items.append(1)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = MutableArgDefaultRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.mutable_arg_default");
}

#[test]
fn mutable_arg_default_flags_dict_default() {
    let body = "def f(opts={}):\n    return opts\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert_eq!(MutableArgDefaultRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn mutable_arg_default_silent_on_none_default() {
    let body = "def f(items=None):\n    items = items or []\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(MutableArgDefaultRule.run(&fx.ctx()).is_empty());
}

// ---------- unused_loop_variable (Phase 9 — Python) ----------------------

#[test]
fn unused_loop_variable_flags_unread_var() {
    let body = "for x in items:\n    print(\"hit\")\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for x in items:".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    let findings = UnusedLoopVariableRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.unused_loop_variable");
}

#[test]
fn unused_loop_variable_silent_when_var_used() {
    let body = "for x in items:\n    print(x)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for x in items:".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    assert!(UnusedLoopVariableRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unused_loop_variable_silent_on_underscore_placeholder() {
    let body = "for _ in range(5):\n    print(\"tick\")\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let loop_id = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Loop)
            .with_prop("header", Value::String("for _ in range(5):".into()))
            .with_prop(
                "range",
                Value::Range(range(
                    1,
                    2,
                    0,
                    u32::try_from(body.len()).unwrap_or(u32::MAX),
                )),
            ),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, loop_id, file)
        .unwrap();
    assert!(UnusedLoopVariableRule.run(&fx.ctx()).is_empty());
}

// ---------- fn_call_in_default_arg (Phase 9 — Python) --------------------

#[test]
fn fn_call_in_default_arg_flags_time_call() {
    let body = "def f(x=time.time()):\n    return x\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FnCallInDefaultArgRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.fn_call_in_default_arg");
}

#[test]
fn fn_call_in_default_arg_silent_on_literal_default() {
    let body = "def f(x=42, y=\"hi\"):\n    return x\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FnCallInDefaultArgRule.run(&fx.ctx()).is_empty());
}

#[test]
fn fn_call_in_default_arg_silent_on_fastapi_depends() {
    let body = "def f(user=Depends(get_user)):\n    return user\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FnCallInDefaultArgRule.run(&fx.ctx()).is_empty());
}

// ---------- assert_with_tuple (Phase 9 — Python) -------------------------

#[test]
fn assert_with_tuple_flags_two_element_tuple() {
    let body = "def f(x, y):\n    assert (x > 0, y > 0)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = AssertWithTupleRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.assert_with_tuple");
}

#[test]
fn assert_with_tuple_silent_on_assert_with_message() {
    // `assert cond, "msg"` — the comma is OUTSIDE the parens, not a tuple.
    let body = "def f(x):\n    assert (x > 0), \"x must be positive\"\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(AssertWithTupleRule.run(&fx.ctx()).is_empty());
}

#[test]
fn assert_with_tuple_silent_on_plain_assert() {
    let body = "def f(x):\n    assert x > 0\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(AssertWithTupleRule.run(&fx.ctx()).is_empty());
}

// ---------- broad_pytest_raises (Phase 9 — Python) -----------------------

#[test]
fn broad_pytest_raises_flags_exception() {
    // Probe explicitly DOES fire on test files for this rule.
    let body = "def test_thing():\n    with pytest.raises(Exception):\n        do()\n";
    let mut fx = Fixture::new().with_source("src/feature.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/feature.py");
    let findings = BroadPytestRaisesRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.broad_pytest_raises");
}

#[test]
fn broad_pytest_raises_silent_on_specific_subclass() {
    let body = "def test_thing():\n    with pytest.raises(ValueError):\n        do()\n";
    let mut fx = Fixture::new().with_source("src/feature.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/feature.py");
    assert!(BroadPytestRaisesRule.run(&fx.ctx()).is_empty());
}

#[test]
fn broad_pytest_raises_flags_base_exception() {
    let body = "def test_thing():\n    with raises(BaseException):\n        do()\n";
    let mut fx = Fixture::new().with_source("src/feature.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/feature.py");
    assert_eq!(BroadPytestRaisesRule.run(&fx.ctx()).len(), 1);
}

// ---------- absurd_extreme_comparison (Phase 9 — Rust) ------------------

use crate::absurd_extreme_comparison::AbsurdExtremeComparisonRule;
use crate::bad_bit_mask::BadBitMaskRule;
use crate::cast_nan_to_int::CastNanToIntRule;
use crate::cast_possible_truncation::CastPossibleTruncationRule;
use crate::cast_precision_loss::CastPrecisionLossRule;

#[test]
fn absurd_extreme_comparison_flags_u8_gt_256() {
    let body = "fn f(n: u32) -> bool {\n    \
                    (n as u8) > 256\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = AbsurdExtremeComparisonRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.absurd_extreme_comparison");
}

#[test]
fn absurd_extreme_comparison_flags_i8_gt_127() {
    let body = "fn f(k: i32) -> bool {\n    \
                    (k as i8) > 127\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(AbsurdExtremeComparisonRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn absurd_extreme_comparison_silent_on_in_range_compare() {
    let body = "fn f(n: u32) -> bool {\n    \
                    (n as u8) > 100\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(AbsurdExtremeComparisonRule.run(&fx.ctx()).is_empty());
}

// ---------- bad_bit_mask (Phase 9 — Rust) -------------------------------

#[test]
fn bad_bit_mask_flags_and_zero_eq_one() {
    let body = "fn f(x: u32) -> bool {\n    \
                    x & 0 == 1\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = BadBitMaskRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.bad_bit_mask");
}

#[test]
fn bad_bit_mask_flags_or_full_mask_compare_zero() {
    let body = "fn f(x: u8) -> bool {\n    \
                    x | 0xff != 0\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(BadBitMaskRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn bad_bit_mask_silent_on_real_flag_check() {
    let body = "fn f(x: u32) -> bool {\n    \
                    x & 0x1 == 1\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(BadBitMaskRule.run(&fx.ctx()).is_empty());
}

// ---------- cast_nan_to_int (Phase 9 — Rust) ----------------------------

#[test]
fn cast_nan_to_int_flags_nan_constant() {
    let body = "fn f() -> u32 {\n    \
                    f64::NAN as u32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = CastNanToIntRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.cast_nan_to_int");
}

#[test]
fn cast_nan_to_int_flags_zero_div_zero() {
    let body = "fn f() -> i32 {\n    \
                    (0.0f64 / 0.0f64) as i32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(CastNanToIntRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn cast_nan_to_int_silent_on_normal_cast() {
    let body = "fn f(x: f64) -> u32 {\n    \
                    x as u32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(CastNanToIntRule.run(&fx.ctx()).is_empty());
}

// ---------- cast_possible_truncation (Phase 9 — Rust) -------------------

#[test]
fn cast_possible_truncation_flags_u64_to_u8() {
    let body = "fn f() -> u8 {\n    \
                    let big: u64 = 1_000_000;\n    \
                    big as u8\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = CastPossibleTruncationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.cast_possible_truncation");
}

#[test]
fn cast_possible_truncation_flags_i64_to_i32() {
    let body = "fn f() -> i32 {\n    \
                    let n: i64 = 5;\n    \
                    n as i32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(CastPossibleTruncationRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn cast_possible_truncation_silent_when_source_unknown() {
    // No declared source type — heuristic must NOT fire.
    let body = "fn f() -> u8 {\n    \
                    something() as u8\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(CastPossibleTruncationRule.run(&fx.ctx()).is_empty());
}

// ---------- cast_precision_loss (Phase 9 — Rust) ------------------------

#[test]
fn cast_precision_loss_flags_i64_to_f32() {
    let body = "fn f() -> f32 {\n    \
                    let n: i64 = 12345;\n    \
                    n as f32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = CastPrecisionLossRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.cast_precision_loss");
}

#[test]
fn cast_precision_loss_flags_i128_to_f64() {
    let body = "fn f() -> f64 {\n    \
                    let big: i128 = 1;\n    \
                    big as f64\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(CastPrecisionLossRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn cast_precision_loss_silent_for_safe_cast() {
    // i32 -> f64 fits exactly; not flagged.
    let body = "fn f() -> f64 {\n    \
                    let n: i32 = 1;\n    \
                    n as f64\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(CastPrecisionLossRule.run(&fx.ctx()).is_empty());
}

// ---------- furb_implicit_int_str_concat (Phase 10 — ruff ISC001) -------

use crate::furb_dict_get_with_none_default::FurbDictGetWithNoneDefaultRule;
use crate::furb_for_else_loop_unused::FurbForElseLoopUnusedRule;
use crate::furb_implicit_int_str_concat::FurbImplicitIntStrConcatRule;

#[test]
fn furb_implicit_concat_flags_adjacent_literals() {
    let body = "names = [\n    \"foo\" \"bar\",\n    \"baz\",\n]\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FurbImplicitIntStrConcatRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.furb_implicit_int_str_concat");
}

#[test]
fn furb_implicit_concat_silent_on_separated_literals() {
    let body = "names = [\"foo\", \"bar\", \"baz\"]\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbImplicitIntStrConcatRule.run(&fx.ctx()).is_empty());
}

#[test]
fn furb_implicit_concat_silent_on_explicit_plus() {
    let body = "msg = \"foo\" + \"bar\"\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbImplicitIntStrConcatRule.run(&fx.ctx()).is_empty());
}

// ---------- furb_dict_get_with_none_default (Phase 10 — ruff FURB186) ---

#[test]
fn furb_dict_get_none_flags_redundant_default() {
    let body = "def lookup(d, key):\n    return d.get(key, None)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FurbDictGetWithNoneDefaultRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.bug.furb_dict_get_with_none_default"
    );
}

#[test]
fn furb_dict_get_none_silent_when_get_has_no_default() {
    let body = "def lookup(d, key):\n    return d.get(key)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbDictGetWithNoneDefaultRule.run(&fx.ctx()).is_empty());
}

#[test]
fn furb_dict_get_none_silent_with_meaningful_default() {
    let body = "def lookup(d, key):\n    return d.get(key, 0)\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbDictGetWithNoneDefaultRule.run(&fx.ctx()).is_empty());
}

// ---------- furb_for_else_loop_unused (Phase 10) -------------------------

#[test]
fn furb_for_else_flags_loop_without_break() {
    let body =
        "def scan(items):\n    for x in items:\n        do(x)\n    else:\n        cleanup()\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FurbForElseLoopUnusedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.furb_for_else_loop_unused");
}

#[test]
fn furb_for_else_silent_when_break_present() {
    let body = "def scan(items):\n    for x in items:\n        if hit(x):\n            break\n    else:\n        miss()\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbForElseLoopUnusedRule.run(&fx.ctx()).is_empty());
}

#[test]
fn furb_for_else_silent_on_for_without_else() {
    let body = "def scan(items):\n    for x in items:\n        do(x)\n    cleanup()\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FurbForElseLoopUnusedRule.run(&fx.ctx()).is_empty());
}

// ---------- duplicate_dict_keys (Phase 10 — ruff F601 / ESLint no-dupe-keys)

use crate::duplicate_dict_keys::DuplicateDictKeysRule;

#[test]
fn duplicate_dict_keys_flags_python_string_dup() {
    let body = "config = {\"a\": 1, \"a\": 2}\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = DuplicateDictKeysRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.duplicate_dict_keys");
}

#[test]
fn duplicate_dict_keys_silent_on_unique_keys() {
    let body = "config = {\"a\": 1, \"b\": 2}\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(DuplicateDictKeysRule.run(&fx.ctx()).is_empty());
}

#[test]
fn duplicate_dict_keys_flags_js_bare_identifier_dup() {
    let body = "const opts = { foo: 1, foo: 2 };\n";
    let mut fx = Fixture::new().with_source("src/app.js", body.as_bytes().to_vec());
    push_file(&mut fx.batch, "src/app.js");
    let findings = DuplicateDictKeysRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- arithmetic_side_effects (Phase 10 — clippy) -----------------

use crate::arithmetic_side_effects::ArithmeticSideEffectsRule;
use crate::as_conversions::AsConversionsRule;
use crate::clone_on_ref_ptr::CloneOnRefPtrRule;
use crate::default_numeric_fallback::DefaultNumericFallbackRule;

#[test]
fn arithmetic_side_effects_flags_sub_under_deny_attr() {
    let body = "#[deny(arithmetic_overflow)]\n\
                fn budget(used: u32, granted: u32) -> u32 {\n    \
                    granted - used\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = ArithmeticSideEffectsRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.arithmetic_side_effects");
}

#[test]
fn arithmetic_side_effects_silent_without_deny_or_security_path() {
    let body = "fn budget(used: u32, granted: u32) -> u32 {\n    \
                    granted - used\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(ArithmeticSideEffectsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn arithmetic_side_effects_silent_on_compound_assign() {
    let body = "#[deny(arithmetic_overflow)]\n\
                fn step(n: &mut u32) {\n    \
                    *n += 1;\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(ArithmeticSideEffectsRule.run(&fx.ctx()).is_empty());
}

// ---------- as_conversions (Phase 10 — clippy) ---------------------------

#[test]
fn as_conversions_flags_ident_to_u8_cast() {
    let body = "fn shrink(big: u64) -> u8 {\n    \
                    big as u8\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = AsConversionsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.as_conversions");
}

#[test]
fn as_conversions_silent_on_typed_literal_cast() {
    let body = "fn f() -> u32 {\n    \
                    0u8 as u32\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(AsConversionsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn as_conversions_silent_in_test_files() {
    let body = "fn f(x: u64) -> u8 { x as u8 }\n";
    let mut fx = Fixture::new().with_source("tests/it.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "tests/it.rs");
    assert!(AsConversionsRule.run(&fx.ctx()).is_empty());
}

// ---------- clone_on_ref_ptr (Phase 10 — clippy) -------------------------

#[test]
fn clone_on_ref_ptr_flags_arc_clone() {
    let body = "fn share() {\n    \
                    let counter = Arc::new(0u32);\n    \
                    let copy = counter.clone();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = CloneOnRefPtrRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.clone_on_ref_ptr");
}

#[test]
fn clone_on_ref_ptr_silent_when_no_arc_binding() {
    let body = "fn share() {\n    \
                    let s = String::from(\"hi\");\n    \
                    let copy = s.clone();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(CloneOnRefPtrRule.run(&fx.ctx()).is_empty());
}

#[test]
fn clone_on_ref_ptr_flags_rc_clone() {
    let body = "fn share() {\n    \
                    let value = Rc::new(42u32);\n    \
                    let same = value.clone();\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert_eq!(CloneOnRefPtrRule.run(&fx.ctx()).len(), 1);
}

// ---------- default_numeric_fallback (Phase 10 — clippy) -----------------

#[test]
fn default_numeric_fallback_flags_unannotated_module_const() {
    let body = "const RETRIES = 5;\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    let findings = DefaultNumericFallbackRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.default_numeric_fallback");
}

#[test]
fn default_numeric_fallback_silent_when_annotated() {
    let body = "const RETRIES: u32 = 5;\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(DefaultNumericFallbackRule.run(&fx.ctx()).is_empty());
}

#[test]
fn default_numeric_fallback_silent_inside_function() {
    // Inside a function the literal sits at non-zero indent — heuristic skips.
    let body = "fn f() {\n    \
                    let n = 5;\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/lib.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.rs");
    assert!(DefaultNumericFallbackRule.run(&fx.ctx()).is_empty());
}

// Phase-11 govet rule unit tests live in `test_phase11.rs` to keep
// this file under the 1500-LOC ceiling.

// ---------- registry integration ----------------------------------------

const REGISTERED_SLUGS: &[&str] = &[
    "cc.bug.null_propagation",
    "cc.bug.off_by_one",
    "cc.bug.type_confusion",
    "cc.bug.state_machine",
    "cc.bug.time_bomb",
    "cc.bug.float_money",
    "cc.bug.locale_dependent",
    "cc.bug.equals_hashcode_pair",
    "cc.bug.identity_binary_expr",
    "cc.bug.cmp_to_nan",
    "cc.bug.shift_amount_oor",
    "cc.bug.format_string_drift",
    "cc.bug.regex_invalid",
    "cc.bug.deferred_close_no_err",
    "cc.bug.mutate_during_iteration",
    "cc.bug.tick_leak",
    "cc.bug.dead_thread",
    "cc.bug.always_throws",
    "cc.bug.use_after_move",
    "cc.bug.html_url_javascript",
    // Phase 9 (Python).
    "cc.bug.mutable_arg_default",
    "cc.bug.unused_loop_variable",
    "cc.bug.fn_call_in_default_arg",
    "cc.bug.assert_with_tuple",
    "cc.bug.broad_pytest_raises",
    // Phase 9 (Go).
    "cc.bug.body_close_missing",
    "cc.bug.errcheck_json",
    "cc.bug.err_named_inconsistently",
    "cc.bug.nilerr",
    // Phase 9 (Rust).
    "cc.bug.absurd_extreme_comparison",
    "cc.bug.bad_bit_mask",
    "cc.bug.cast_nan_to_int",
    "cc.bug.cast_possible_truncation",
    "cc.bug.cast_precision_loss",
    // Phase 10 (Python long-tail — FURB / ISC).
    "cc.bug.furb_implicit_int_str_concat",
    "cc.bug.furb_dict_get_with_none_default",
    "cc.bug.furb_for_else_loop_unused",
    // Phase 10 (Batch L — multi-language cross-cutting).
    "cc.bug.duplicate_dict_keys",
    // Phase 10 (Rust long-tail — clippy).
    "cc.bug.arithmetic_side_effects",
    "cc.bug.as_conversions",
    "cc.bug.clone_on_ref_ptr",
    "cc.bug.default_numeric_fallback",
    // Phase 11 (Go govet long-tail).
    "cc.bug.govet_unreachable_code",
    "cc.bug.govet_lostcancel",
    "cc.bug.govet_assign_to_self",
    "cc.bug.govet_copylocks",
    "cc.bug.govet_unkeyed_composite",
    // Phase 12 (final OSS long-tail sweep).
    "cc.bug.govet_nilness_check",
    "cc.bug.govet_printf_format",
    "cc.bug.govet_struct_tag_well_formed",
    "cc.bug.python_assert_in_production",
    // Batch 2 (Python reliability probes).
    "cc.bug.callout_under_lock",
    "cc.bug.one_ticket_per_refusal",
    "cc.bug.unbounded_detail_text",
];

#[test]
fn builtin_pack_registers_fifty_four_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinBugsPack)
        .expect("Family-3 pack registers without error");
    assert_eq!(reg.rules().count(), 54);
    for slug in REGISTERED_SLUGS {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

fn batch2_findings(rule_id: &str, path: &str, source: &[u8]) -> Vec<cc_finding::Finding> {
    let mut registry = RuleRegistry::new();
    registry.register_pack(&BuiltinBugsPack).unwrap();
    let mut fixture = Fixture::new().with_source(path, source.to_vec());
    push_file(&mut fixture.batch, path);
    registry
        .rule_by_id(rule_id)
        .map_or_else(Vec::new, |rule| rule.run(&fixture.ctx()))
}

#[test]
fn callout_under_lock_reports_external_calls() {
    let source = br#"import threading as threads
from threading import RLock as Reentrant
process_gate = threads.Lock()
class Worker:
    def __init__(self, output: Callable):
        self._dispatch = output
        self.gate = Reentrant()
    def run(self, on_ready=None):
        with self.gate as held:
            self._dispatch()
            on_ready()
        with (other, self.mutex):
            self.bus.publish()
            self.notify_ready()
        with process_gate:
            transport.send()
        gate = threads.Lock()
        with gate:
            self.reporter.file()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [10, 11, 13, 14, 16, 19]
    );
    assert!(findings
        .iter()
        .all(|hit| hit.severity == cc_finding::Severity::Required));
}

#[test]
fn callout_under_lock_skips_own_helpers_lock_methods_and_deferred_calls() {
    let source = br#"class Worker:
    def _emit(self):
        pass
    def run(self, handler):
        with self.guard:
            self._emit()
            self.guard.notify()
            self.guard.acquire()
            def later():
                handler()
            job = lambda: handler()
        handler()
        with other:
            service.publish()
def emit():
    pass
with lock:
    emit()
"#;
    assert!(batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source).is_empty());
}

#[test]
fn callout_under_lock_tracks_attribute_bindings_and_injected_tuple_slots() {
    let source = br#"from threading import Lock
class Worker:
    global_gate = Lock()
    def __init__(self, output):
        self._port, self._count = output, 0
        self.callback = self._refresh
    def _refresh(self):
        pass
    def run(self, state):
        state.gate = Lock()
        with state.gate:
            self._port()
            self.callback()
        with self.global_gate:
            service.handle()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [12, 15]
    );
}

#[test]
fn callout_under_lock_follows_a_private_helper_to_an_injected_receiver() {
    let source = br#"import threading
class Settings:
    def __init__(self, book):
        self._book = book
        self._lock, self._save_lock = threading.Lock(), threading.Lock()
    def change(self, choices):
        with self._save_lock:
            with self._lock:
                choices = dict(choices)
            self._save(choices)
    def release(self, choices):
        self._save(choices)
    def _save(self, choices):
        if self._book is not None:
            self._book.save(choices)
        self._deeper(choices)
    def _deeper(self, choices):
        self._book.save(choices)
    def direct(self, choices):
        with self._save_lock:
            self._book.save(choices)
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/settings.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [15, 21]
    );
}

#[test]
fn callout_under_lock_tracks_explicit_acquire_and_matching_release() {
    let source = br#"class Gate:
    def straight(self):
        self._write_lock.acquire()
        other_lock.release()
        self.transport.send()
        self._write_lock.release()
        self.transport.send()
    def guarded(self):
        self._write_lock.acquire()
        try:
            self.transport.send()
        finally:
            self.transport.notify()
            self._write_lock.release()
            self.transport.send()
        self.transport.send()
    def flush(self):
        self._write_lock.acquire()
        self._flush_held()
        self.transport.send()
    def try_flush(self):
        if self._write_lock.acquire(timeout=0):
            self._flush_held()
    def _flush_held(self):
        try:
            self.transport.send()
        finally:
            self._write_lock.release()
        self.transport.send()
    def no_match(self):
        self._write_lock.acquire()
        self.transport.send()
        other_lock.release()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/gate.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [5, 11, 13, 26]
    );
}

#[test]
fn one_ticket_per_refusal_reports_unguarded_filing_and_downgrades_tests() {
    let source = br#"def act(verdict, sink):
    try:
        run()
    except OSError:
        sink.fault("WRITE", "failed")
    if verdict.allowed:
        proceed()
    else:
        sink.file("GUARD", "place", "denied")
    if not verdict.refused:
        proceed()
    else:
        report_fault("GUARD", "denied")
    if verdict.allowed:
        proceed()
    elif verdict.pending:
        wait()
    else:
        ticket("GUARD", "place")
"#;
    for (path, severity) in [
        ("app/worker.py", cc_finding::Severity::Required),
        ("app/test_worker.py", cc_finding::Severity::Nit),
    ] {
        let findings = batch2_findings("cc.bug.one_ticket_per_refusal", path, source);
        assert_eq!(
            findings
                .iter()
                .map(|hit| hit.location.start.line)
                .collect::<Vec<_>>(),
            [5, 9, 13, 19]
        );
        assert!(findings.iter().all(|hit| hit.severity == severity));
    }
}

#[test]
fn one_ticket_per_refusal_accepts_prior_dedupe_checks() {
    let source = br#"def act(sink, code, place, seen):
    try:
        run()
    except OSError:
        key = code, place
        if key in seen:
            return
        seen.add(key)
        sink.file(code, place, "failed")
def fork(sink, key, cache):
    try:
        run()
    except OSError:
        if key not in cache:
            cache.add(key)
            file_fault(key)
def write(sink, allowed, already_filed):
    if allowed:
        proceed()
    else:
        if not already_filed:
            sink.fault("WRITE", "failed")
"#;
    assert!(batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source).is_empty());
}

#[test]
fn one_ticket_per_refusal_limits_scope_and_requires_a_real_guard() {
    let source = br#"def act(sink, ready, key):
    if ready:
        proceed()
    else:
        sink.file("NORMAL", "where", "not a refusal")
    try:
        run()
    except OSError:
        def later():
            sink.fault("DEFERRED", "not an exception handler")
        def unrelated(tickets):
            if key in tickets:
                return
        if key not in "abc":
            sink.report_fault("WRITE", "failed")
        if already_filed:
            return
"#;
    let findings = batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [15]
    );
}

#[test]
fn one_ticket_per_refusal_checks_membership_writes_and_private_guards() {
    let source = br#"class Worker:
    def remember(self, key):
        self._seen.setdefault(key, True)
    def run(self, sink, k):
        recorded = {}
        pending = []
        try:
            work()
        except OSError:
            if k in ALLOWED:
                sink.fault("ALLOWED", "failed")
            if k in READ_ONLY_TICKETS:
                sink.fault("FILTER", "failed")
            if k not in self._seen:
                sink.fault("SEEN", "failed")
            if k not in recorded:
                recorded[k] = True
                sink.fault("RECORDED", "failed")
            if k not in pending:
                pending.append(k)
                sink.fault("PENDING", "failed")
            if self._is_new(k):
                sink.fault("NEW", "failed")
            if self._first_failure(k):
                sink.fault("FIRST", "failed")
            if not self._already_seen(k):
                sink.fault("UNSEEN", "failed")
            if self._renew(k):
                sink.fault("RENEW", "failed")
"#;
    let findings = batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [11, 13, 29]
    );
}

#[test]
fn unbounded_detail_text_reports_converted_errors_and_payloads() {
    let source = br#"from dataclasses import dataclass
@dataclass
class Notice:
    code: str
    what: str
    description: str = ""
def publish(code, message):
    pass
def record(value, payload, exc, error, sink):
    sink(detail=str(value))
    record = {"why": repr(payload)}
    sink.todo = format(exc)
    try:
        run()
    except OSError as failure:
        sink.message = f"{failure}"
        notice = Notice("WRITE", f"{failure!r}")
        raw = str(failure)
        publish("WRITE", "could not write: " + raw)
        record["reason"] = format((failure))
        sink(reason=f"{error!r}")
        notice = Notice("WRITE", "failed", description=repr(failure))
        key = "why"
        record[key] = str(failure)
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [10, 11, 12, 16, 17, 19, 20, 21, 24]
    );
    assert!(findings
        .iter()
        .all(|hit| hit.severity == cc_finding::Severity::Required));
}

#[test]
fn unbounded_detail_text_accepts_bounding_and_ignores_unrelated_text() {
    let source = br#"def record(payload, sink, ordinary):
    sink(detail=plain_text(payload, LIMIT))
    sink(detail=clip(str(payload)))
    sink(detail=formatter.shorten(f"{payload!r}"))
    sink(detail=(repr(payload))[:LIMIT])
    sink(detail=wrapper((f"{payload}")[:128]))
    sink(detail=f"error: {truncate(format(payload))}")
    sink(detail=str(ordinary))
    sink(result=repr(payload))
    sink(detail=len(str(payload)))
    sink(detail="present" if str(payload) else "empty")
    raw = str(payload)
    sink(detail=bound_detail(raw))
    payload = "a safe string"
    sink(detail=str(payload))
def unrelated(sink):
    value = "constant"
    sink(detail=str(value))
def other(error, str):
    send(detail=str(error))
try:
    run()
except OSError as failure:
    log(str(failure))
else:
    sink(detail=f"{failure}")
"#;
    assert!(batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source).is_empty());
}

#[test]
fn unbounded_detail_text_tracks_exception_args_and_whole_bounding_names() {
    let source = br#"from reporting import plain_text as pt
import reporting as reports
def record(sink):
    try:
        run()
    except ValueError as e:
        sink(detail=f"{e.args}")
        sink(detail=inbound(str(e)))
        sink(detail=reports.plain_textual(str(e)))
        sink(detail=pt(str(e), 100))
        sink(detail=reports.clip_detail(str(e)))
        sink(detail=bounded(f"{e.args}"))
        sink(detail=f"{e.code}")
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
}

#[test]
fn unbounded_detail_text_requires_a_real_slice_bound() {
    let source = br#"def record(payload, sink):
    sink(detail=str(payload)[:])
    sink(detail=repr(payload)[::-1])
    sink(detail=clip(str(payload)) + f"{payload}")
    sink(detail=f"{payload}"[:self.limit])
    sink(detail=f"{payload}"[:None])
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [2, 3, 4, 6]
    );
}

#[test]
fn unbounded_detail_text_ignores_other_sink_names() {
    let source = br#"from dataclasses import dataclass
@dataclass
class Issue:
    text: str
@dataclass
class Audit:
    issues: tuple[Issue, ...]
def audit():
    try:
        read()
    except OSError as error:
        self.cause = str(error)
        record = {"code": str(error)}
        record["code"] = str(error)
        sink(code=str(error))
        return Audit((Issue(f"unreadable: {error}"),))
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/audit.py", source);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn unbounded_detail_text_resolves_imported_signatures_and_typed_receivers() {
    let use_site = br#"from .reporting import Reporter, fail as refusal
class Holder:
    reporter: Reporter
class Worker:
    def __init__(self, reporter: Reporter):
        self.forwarded = reporter
    def run(self, holder: Holder):
        try:
            read()
        except OSError as err:
            self.forwarded.fault("READ", str(err))
            holder.reporter.fault("READ", f"{err!r}")
            raise refusal("READ", repr(err))
"#;
    let declaration = br#"class Reporter:
    def fault(self, code, detail):
        pass
def fail(code, why):
    return ValueError(why)
"#;
    let mut fixture = Fixture::new()
        .with_source("app/worker.py", use_site)
        .with_source("app/reporting.py", declaration);
    push_file(&mut fixture.batch, "app/worker.py");
    let findings = crate::unbounded_detail_text::UnboundedDetailTextRule.run(&fixture.ctx());
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [11, 12, 13]
    );
}

#[test]
fn one_ticket_per_refusal_accepts_verified_dedupe_in_imported_sink() {
    let use_site = br#"from app.reporting import Dedupe, Raw, Filtered
class Worker:
    def __init__(self, shared: Dedupe):
        self.created = Dedupe()
        self.forwarded, self.raw = shared, Raw()
        self.filtered = Filtered()
    def run(self):
        try:
            read()
        except OSError:
            self.created.file("READ", "home", "failed")
            self.forwarded.file("READ", "home", "failed")
            self.raw.file("READ", "home", "failed")
            self.filtered.file("READ", "home", "failed")
"#;
    let declaration = br#"class Dedupe:
    def __init__(self):
        self._lock = Lock()
        self._open = {}
    def file(self, code, place, detail):
        with self._lock:
            codes = self._open.setdefault(place, set())
            if code in codes:
                return
            codes.add(code)
        sink.fault(code, detail)
class Raw:
    def file(self, code, place, detail):
        seen = set()
        if (code, place) in seen:
            return
        sink.fault(code, detail)
class Filtered:
    def file(self, code, place, detail):
        if code in self.disabled:
            return
        sink.fault(code, detail)
"#;
    let mut fixture = Fixture::new()
        .with_source("app/worker.py", use_site)
        .with_source("app/reporting.py", declaration);
    push_file(&mut fixture.batch, "app/worker.py");
    let findings = crate::one_ticket_per_refusal::OneTicketPerRefusalRule.run(&fixture.ctx());
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [13, 14]
    );
}

#[test]
fn one_ticket_per_refusal_leaves_a_single_filing_test_and_flags_repetition() {
    let source = br#"def test_one_fault_is_recorded():
    sink = Recorder()
    try:
        raise OSError("test trigger")
    except OSError:
        sink.fault("READ", "failed")
    assert sink.events[0].code == "READ"
def test_faults_can_duplicate():
    sink = Recorder()
    for _ in range(3):
        try:
            raise OSError("test trigger")
        except OSError:
            sink.fault("READ", "failed")
    assert sink.events[0].code == "READ"
"#;
    let findings = batch2_findings(
        "cc.bug.one_ticket_per_refusal",
        "tests/test_worker.py",
        source,
    );
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [14]
    );
    assert_eq!(findings[0].severity, cc_finding::Severity::Nit);
}
