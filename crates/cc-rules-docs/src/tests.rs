//! Per-rule unit tests + a pack-registration integration test.

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::dead_link::DeadLinkRule;
use crate::docstring_coverage::DocstringCoverageRule;
use crate::docstring_first_line_imperative::DocstringFirstLineImperativeRule;
use crate::docstring_first_line_period::DocstringFirstLinePeriodRule;
use crate::docstring_signature_drift::DocstringSignatureDriftRule;
use crate::docstring_summary_blank_line::DocstringSummaryBlankLineRule;
use crate::example_doesnt_compile::ExampleDoesntCompileRule;
use crate::readme_install_broken::ReadmeInstallBrokenRule;
use crate::BuiltinDocsPack;

const SAMPLE_PATH: &str = "src/lib.rs";

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

fn push_function(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    rng: Range,
    is_pub: bool,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng))
            .with_prop("is_pub", Value::Bool(is_pub))
            .with_prop(
                "visibility",
                Value::String(if is_pub {
                    "public".into()
                } else {
                    "private".into()
                }),
            ),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_param(batch: &mut CpgWriteBatch, function: NodeId, name: &str, position: u64) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Parameter)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("position", Value::Uint(position))
            .with_prop("is_self", Value::Bool(false)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, function).unwrap();
    id
}

fn push_comment(batch: &mut CpgWriteBatch, parent: NodeId, text: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Comment)
            .with_prop("text", Value::String(text.to_owned()))
            .with_prop("kind", Value::String("line".into()))
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

// ---------- stubs -------------------------------------------------------

#[test]
fn readme_install_broken_is_stub_silent() {
    let fx = Fixture::new();
    assert!(ReadmeInstallBrokenRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        ReadmeInstallBrokenRule.rule_id(),
        "cc.docs.readme_install_broken"
    );
}

#[test]
fn dead_link_is_stub_silent() {
    let fx = Fixture::new();
    assert!(DeadLinkRule.run(&fx.ctx()).is_empty());
    assert_eq!(DeadLinkRule.rule_id(), "cc.docs.dead_link");
}

#[test]
fn example_doesnt_compile_is_stub_silent() {
    let fx = Fixture::new();
    assert!(ExampleDoesntCompileRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        ExampleDoesntCompileRule.rule_id(),
        "cc.docs.example_doesnt_compile"
    );
}

// ---------- docstring_signature_drift ----------------------------------

#[test]
fn signature_drift_flags_param_mismatch() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_comment(
        &mut fx.batch,
        file,
        "\"\"\"Send mail.\n\n:param recipient: address.\n:param subject: text.\n\"\"\"",
        range(1, 4, 0, 80),
    );
    let function = push_function(&mut fx.batch, file, "send", range(5, 8, 81, 200), true);
    push_param(&mut fx.batch, function, "recipient", 0);
    push_param(&mut fx.batch, function, "body", 1);
    let findings = DocstringSignatureDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.docs.docstring_signature_drift");
}

#[test]
fn signature_drift_silent_when_aligned() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_comment(
        &mut fx.batch,
        file,
        "\"\"\"Add two numbers.\n\n:param x: first.\n:param y: second.\n\"\"\"",
        range(1, 4, 0, 80),
    );
    let function = push_function(&mut fx.batch, file, "add", range(5, 8, 81, 200), true);
    push_param(&mut fx.batch, function, "x", 0);
    push_param(&mut fx.batch, function, "y", 1);
    assert!(DocstringSignatureDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- docstring_coverage ----------------------------------------

#[test]
fn coverage_flags_undocumented_public_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "greet", range(10, 12, 200, 300), true);
    let findings = DocstringCoverageRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.docs.docstring_coverage");
}

#[test]
fn coverage_silent_on_documented_public_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_comment(
        &mut fx.batch,
        file,
        "\"\"\"Greet the user.\"\"\"",
        range(9, 9, 180, 200),
    );
    push_function(&mut fx.batch, file, "greet", range(10, 12, 200, 300), true);
    assert!(DocstringCoverageRule.run(&fx.ctx()).is_empty());
}

#[test]
fn coverage_silent_on_private_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "helper",
        range(10, 12, 200, 300),
        false,
    );
    assert!(DocstringCoverageRule.run(&fx.ctx()).is_empty());
}

// ---------- docstring_first_line_period (Phase 10 — ruff D400) -------

const PY_SAMPLE_PATH: &str = "src/sample.py";

fn fx_with_py_source(body: &str) -> Fixture {
    let mut fx = Fixture::new();
    let _ = push_file(&mut fx.batch, PY_SAMPLE_PATH);
    fx.source.insert(
        camino::Utf8PathBuf::from(PY_SAMPLE_PATH),
        body.as_bytes().to_vec(),
    );
    fx
}

#[test]
fn first_line_period_flags_missing_terminator() {
    let body = "def greet(name):\n    \"\"\"Send a greeting\"\"\"\n    return name\n";
    let fx = fx_with_py_source(body);
    let findings = DocstringFirstLinePeriodRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.docs.docstring_first_line_period");
}

#[test]
fn first_line_period_silent_when_terminated() {
    let body = "def greet(name):\n    \"\"\"Send a greeting.\"\"\"\n    return name\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringFirstLinePeriodRule.run(&fx.ctx()).is_empty());
}

#[test]
fn first_line_period_silent_for_question_mark() {
    let body = "def greet(name):\n    \"\"\"What is your name?\"\"\"\n    return name\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringFirstLinePeriodRule.run(&fx.ctx()).is_empty());
}

// ---------- docstring_first_line_imperative (Phase 10 — ruff D401) ---

#[test]
fn first_line_imperative_flags_third_person_returns() {
    let body = "def total():\n    \"\"\"Returns the running total.\"\"\"\n    return 0\n";
    let fx = fx_with_py_source(body);
    let findings = DocstringFirstLineImperativeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.docs.docstring_first_line_imperative"
    );
}

#[test]
fn first_line_imperative_silent_on_imperative_verb() {
    let body = "def total():\n    \"\"\"Return the running total.\"\"\"\n    return 0\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringFirstLineImperativeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn first_line_imperative_silent_on_allowlisted_verb() {
    // "Is" is on the imperative-allowlist for state verbs.
    let body = "def is_ready():\n    \"\"\"Is the system ready.\"\"\"\n    return True\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringFirstLineImperativeRule.run(&fx.ctx()).is_empty());
}

// ---------- docstring_summary_blank_line (Phase 10 — ruff D205) ------

#[test]
fn summary_blank_line_flags_missing_blank() {
    let body = "def add(x, y):\n    \"\"\"Add two numbers.\n    Returns their sum.\n    \"\"\"\n    return x + y\n";
    let fx = fx_with_py_source(body);
    let findings = DocstringSummaryBlankLineRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.docs.docstring_summary_blank_line");
}

#[test]
fn summary_blank_line_silent_when_blank_present() {
    let body = "def add(x, y):\n    \"\"\"Add two numbers.\n\n    Returns their sum.\n    \"\"\"\n    return x + y\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringSummaryBlankLineRule.run(&fx.ctx()).is_empty());
}

#[test]
fn summary_blank_line_silent_on_single_line_docstring() {
    let body = "def add(x, y):\n    \"\"\"Add two numbers.\"\"\"\n    return x + y\n";
    let fx = fx_with_py_source(body);
    assert!(DocstringSummaryBlankLineRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration --------------------------------------

#[test]
fn builtin_pack_registers_eight_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinDocsPack)
        .expect("Family-16 pack registers without error");
    assert_eq!(reg.rules().count(), 8);
    for slug in [
        "cc.docs.readme_install_broken",
        "cc.docs.docstring_signature_drift",
        "cc.docs.docstring_coverage",
        "cc.docs.dead_link",
        "cc.docs.example_doesnt_compile",
        // Phase 10 (Python long-tail).
        "cc.docs.docstring_first_line_period",
        "cc.docs.docstring_first_line_imperative",
        "cc.docs.docstring_summary_blank_line",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
