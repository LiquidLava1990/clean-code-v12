//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has at least one positive (violating) case, one
//! negative (clean) case, and one test-file-skip case. The keyboard-trap
//! stub is verified at the registry level only. The pack-level test
//! confirms all five rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::color_only_signal::ColorOnlySignalRule;
use crate::hardcoded_locale::HardcodedLocaleRule;
use crate::keyboard_trap::KeyboardTrapRule;
use crate::missing_alt::MissingAltRule;
use crate::unicode_unsafe_op::UnicodeUnsafeOpRule;
use crate::BuiltinI18nA11yPack;

// ---------- shared fixtures ----------------------------------------------

const SAMPLE_PY: &str = "src/sample.py";
const SAMPLE_TSX: &str = "src/sample.tsx";
const SAMPLE_TEST_TSX: &str = "tests/sample.tsx";

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

fn push_literal(batch: &mut CpgWriteBatch, parent: NodeId, value: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String(value.to_owned()))
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

// ---------- hardcoded_locale --------------------------------------------

#[test]
fn hardcoded_locale_flags_en_us_string() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PY, "python");
    push_literal(
        &mut fx.batch,
        file,
        "format date in en_US locale",
        range(1, 1, 0, 30),
    );
    let findings = HardcodedLocaleRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.i18n.hardcoded_locale");
}

#[test]
fn hardcoded_locale_silent_on_unrelated_string() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PY, "python");
    push_literal(&mut fx.batch, file, "hello world", range(1, 1, 0, 11));
    assert!(HardcodedLocaleRule.run(&fx.ctx()).is_empty());
}

#[test]
fn hardcoded_locale_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/sample.py", "python");
    push_literal(&mut fx.batch, file, "en_US", range(1, 1, 0, 5));
    assert!(HardcodedLocaleRule.run(&fx.ctx()).is_empty());
}

#[test]
fn hardcoded_locale_flags_iana_timezone() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PY, "python");
    push_literal(&mut fx.batch, file, "Europe/Paris", range(1, 1, 0, 12));
    assert_eq!(HardcodedLocaleRule.run(&fx.ctx()).len(), 1);
}

// ---------- unicode_unsafe_op -------------------------------------------

#[test]
fn unicode_unsafe_flags_len_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PY, "python");
    push_call(&mut fx.batch, file, "len(s", range(1, 1, 0, 6));
    let findings = UnicodeUnsafeOpRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.i18n.unicode_unsafe_op");
}

#[test]
fn unicode_unsafe_silent_on_unrelated_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PY, "python");
    push_call(&mut fx.batch, file, "print(s)", range(1, 1, 0, 8));
    assert!(UnicodeUnsafeOpRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unicode_unsafe_skips_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/foo_test.py", "python");
    push_call(&mut fx.batch, file, "len(s", range(1, 1, 0, 6));
    assert!(UnicodeUnsafeOpRule.run(&fx.ctx()).is_empty());
}

// ---------- missing_alt -------------------------------------------------

#[test]
fn missing_alt_flags_img_without_alt() {
    let body = "const X = () => <img src=\"a.png\" />;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TSX, "tsx");
    let findings = MissingAltRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.a11y.missing_alt");
}

#[test]
fn missing_alt_silent_when_alt_present() {
    let body = "const X = () => <img src=\"a.png\" alt=\"logo\" />;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TSX, "tsx");
    assert!(MissingAltRule.run(&fx.ctx()).is_empty());
}

#[test]
fn missing_alt_skips_test_files() {
    let body = "const X = () => <img src=\"a.png\" />;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TEST_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TEST_TSX, "tsx");
    assert!(MissingAltRule.run(&fx.ctx()).is_empty());
}

// ---------- color_only_signal -------------------------------------------

#[test]
fn color_only_flags_inline_red_without_icon() {
    let body = "const Err = () => <span style=\"color: red\">Failed</span>;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TSX, "tsx");
    let findings = ColorOnlySignalRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.a11y.color_only_signal");
}

#[test]
fn color_only_silent_when_icon_nearby() {
    let body = "const Err = () => <span style=\"color: red\" aria-label=\"error\">!</span>;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TSX, "tsx");
    assert!(ColorOnlySignalRule.run(&fx.ctx()).is_empty());
}

#[test]
fn color_only_skips_test_files() {
    let body = "const Err = () => <span style=\"color: red\">Failed</span>;\n";
    let mut fx = Fixture::new().with_source(SAMPLE_TEST_TSX, body.as_bytes().to_vec());
    push_file(&mut fx.batch, SAMPLE_TEST_TSX, "tsx");
    assert!(ColorOnlySignalRule.run(&fx.ctx()).is_empty());
}

// ---------- keyboard_trap (stub) ----------------------------------------

#[test]
fn keyboard_trap_stub_emits_nothing() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, SAMPLE_TSX, "tsx");
    assert!(KeyboardTrapRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinI18nA11yPack)
        .expect("Family-15 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.i18n.hardcoded_locale",
        "cc.i18n.unicode_unsafe_op",
        "cc.a11y.missing_alt",
        "cc.a11y.color_only_signal",
        "cc.a11y.keyboard_trap",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
