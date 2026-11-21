//! Per-probe unit tests + a pack-registration integration test.
//!
//! Every rule has at least one positive (violating) case, one negative
//! (clean) case, and a test-fixture-skip case. The pack-level test
//! confirms the registry holds exactly ten rules with the expected
//! slugs.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::bom_present::BomPresentRule;
use crate::crlf_line_endings::CrlfLineEndingsRule;
use crate::inconsistent_string_quotes::InconsistentStringQuotesRule;
use crate::long_line::LongLineRule;
use crate::mixed_indentation::MixedIndentationRule;
use crate::multiple_blank_lines::MultipleBlankLinesRule;
use crate::no_final_newline::NoFinalNewlineRule;
use crate::tab_in_python::TabInPythonRule;
use crate::todo_no_owner::TodoNoOwnerRule;
use crate::trailing_whitespace::TrailingWhitespaceRule;
use crate::BuiltinFormattingPack;

// ---------- shared fixtures -----------------------------------------------

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

    fn with_file(mut self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        push_file(&mut self.batch, path);
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

// ---------- trailing_whitespace -------------------------------------------

#[test]
fn trailing_whitespace_flags_space_at_eol() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1   \ny = 2\n".to_vec());
    let findings = TrailingWhitespaceRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.fmt.trailing_whitespace");
}

#[test]
fn trailing_whitespace_silent_on_clean_file() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\ny = 2\n".to_vec());
    assert!(TrailingWhitespaceRule.run(&fx.ctx()).is_empty());
}

#[test]
fn trailing_whitespace_skips_test_fixture() {
    let fx = Fixture::new().with_file("tests/sample.py", b"x = 1   \n".to_vec());
    assert!(TrailingWhitespaceRule.run(&fx.ctx()).is_empty());
}

// ---------- mixed_indentation ---------------------------------------------

#[test]
fn mixed_indentation_flags_tab_and_space_mix() {
    let bytes = b"def f():\n\treturn 1\ndef g():\n    return 2\n".to_vec();
    let fx = Fixture::new().with_file("src/a.py", bytes);
    let findings = MixedIndentationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn mixed_indentation_silent_when_consistent() {
    let bytes = b"def f():\n    return 1\ndef g():\n    return 2\n".to_vec();
    let fx = Fixture::new().with_file("src/a.py", bytes);
    assert!(MixedIndentationRule.run(&fx.ctx()).is_empty());
}

#[test]
fn mixed_indentation_skips_test_fixture() {
    let bytes = b"def f():\n\treturn 1\ndef g():\n    return 2\n".to_vec();
    let fx = Fixture::new().with_file("tests/a.py", bytes);
    assert!(MixedIndentationRule.run(&fx.ctx()).is_empty());
}

// ---------- tab_in_python -------------------------------------------------

#[test]
fn tab_in_python_flags_tab_indent() {
    let fx = Fixture::new().with_file("src/a.py", b"def f():\n\treturn 1\n".to_vec());
    let findings = TabInPythonRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn tab_in_python_silent_on_space_indent() {
    let fx = Fixture::new().with_file("src/a.py", b"def f():\n    return 1\n".to_vec());
    assert!(TabInPythonRule.run(&fx.ctx()).is_empty());
}

#[test]
fn tab_in_python_skips_test_fixture() {
    let fx = Fixture::new().with_file("tests/a.py", b"def f():\n\treturn 1\n".to_vec());
    assert!(TabInPythonRule.run(&fx.ctx()).is_empty());
}

// ---------- crlf_line_endings ---------------------------------------------

#[test]
fn crlf_flags_dos_line_endings() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\r\ny = 2\r\n".to_vec());
    let findings = CrlfLineEndingsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn crlf_silent_on_lf_only() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\ny = 2\n".to_vec());
    assert!(CrlfLineEndingsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn crlf_skips_test_fixture() {
    let fx = Fixture::new().with_file("tests/a.py", b"x = 1\r\n".to_vec());
    assert!(CrlfLineEndingsRule.run(&fx.ctx()).is_empty());
}

// ---------- bom_present ---------------------------------------------------

#[test]
fn bom_flags_utf8_bom_prefix() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"x = 1\n");
    let fx = Fixture::new().with_file("src/a.py", bytes);
    let findings = BomPresentRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn bom_silent_on_plain_ascii() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\n".to_vec());
    assert!(BomPresentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bom_skips_test_fixture() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"x = 1\n");
    let fx = Fixture::new().with_file("tests/a.py", bytes);
    assert!(BomPresentRule.run(&fx.ctx()).is_empty());
}

// ---------- no_final_newline ----------------------------------------------

#[test]
fn no_final_newline_flags_missing_trailing_lf() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1".to_vec());
    let findings = NoFinalNewlineRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn no_final_newline_silent_when_present() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\n".to_vec());
    assert!(NoFinalNewlineRule.run(&fx.ctx()).is_empty());
}

#[test]
fn no_final_newline_skips_test_fixture() {
    let fx = Fixture::new().with_file("tests/a.py", b"x = 1".to_vec());
    assert!(NoFinalNewlineRule.run(&fx.ctx()).is_empty());
}

// ---------- multiple_blank_lines ------------------------------------------

#[test]
fn multiple_blank_lines_flags_three_blank_run() {
    let bytes = b"x = 1\n\n\n\ny = 2\n".to_vec();
    let fx = Fixture::new().with_file("src/a.py", bytes);
    let findings = MultipleBlankLinesRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn multiple_blank_lines_silent_on_two_blank_run() {
    let bytes = b"x = 1\n\n\ny = 2\n".to_vec();
    let fx = Fixture::new().with_file("src/a.py", bytes);
    assert!(MultipleBlankLinesRule.run(&fx.ctx()).is_empty());
}

#[test]
fn multiple_blank_lines_skips_test_fixture() {
    let bytes = b"x = 1\n\n\n\ny = 2\n".to_vec();
    let fx = Fixture::new().with_file("tests/a.py", bytes);
    assert!(MultipleBlankLinesRule.run(&fx.ctx()).is_empty());
}

// ---------- inconsistent_string_quotes ------------------------------------

#[test]
fn inconsistent_quotes_flags_mixed_python_file() {
    // 1 single + 30 double => minority share ~3% — under threshold, NOT flagged.
    // 4 single + 20 double => minority share ~17% — flagged.
    let mut body = String::new();
    for _ in 0..2 {
        body.push_str("x = 'a'\n");
    }
    for _ in 0..10 {
        body.push_str("y = \"b\"\n");
    }
    let fx = Fixture::new().with_file("src/a.py", body.into_bytes());
    let findings = InconsistentStringQuotesRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn inconsistent_quotes_silent_when_consistent() {
    let mut body = String::new();
    for _ in 0..15 {
        body.push_str("y = \"b\"\n");
    }
    let fx = Fixture::new().with_file("src/a.py", body.into_bytes());
    assert!(InconsistentStringQuotesRule.run(&fx.ctx()).is_empty());
}

#[test]
fn inconsistent_quotes_skips_test_fixture() {
    let mut body = String::new();
    for _ in 0..2 {
        body.push_str("x = 'a'\n");
    }
    for _ in 0..10 {
        body.push_str("y = \"b\"\n");
    }
    let fx = Fixture::new().with_file("tests/a.py", body.into_bytes());
    assert!(InconsistentStringQuotesRule.run(&fx.ctx()).is_empty());
}

// ---------- long_line -----------------------------------------------------

#[test]
fn long_line_flags_overlength_line() {
    let long = "x = ".to_string() + &"a".repeat(200) + "\n";
    let fx = Fixture::new().with_file("src/a.py", long.into_bytes());
    let findings = LongLineRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn long_line_silent_on_short_lines() {
    let fx = Fixture::new().with_file("src/a.py", b"x = 1\ny = 2\n".to_vec());
    assert!(LongLineRule.run(&fx.ctx()).is_empty());
}

#[test]
fn long_line_skips_url_lines() {
    let body = format!("x = \"https://example.com/{}\"\n", "a".repeat(200));
    let fx = Fixture::new().with_file("src/a.py", body.into_bytes());
    assert!(LongLineRule.run(&fx.ctx()).is_empty());
}

#[test]
fn long_line_skips_test_fixture() {
    let long = "x = ".to_string() + &"a".repeat(200) + "\n";
    let fx = Fixture::new().with_file("tests/a.py", long.into_bytes());
    assert!(LongLineRule.run(&fx.ctx()).is_empty());
}

// ---------- todo_no_owner -------------------------------------------------

#[test]
fn todo_no_owner_flags_bare_todo() {
    let fx = Fixture::new().with_file("src/a.py", b"# TODO: rewrite this\nx = 1\n".to_vec());
    let findings = TodoNoOwnerRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn todo_no_owner_silent_when_owner_present_paren() {
    let fx = Fixture::new().with_file("src/a.py", b"# TODO(alice): rewrite\nx = 1\n".to_vec());
    assert!(TodoNoOwnerRule.run(&fx.ctx()).is_empty());
}

#[test]
fn todo_no_owner_silent_when_owner_present_at_handle() {
    let fx = Fixture::new().with_file("src/a.py", b"# TODO(@alice): rewrite\nx = 1\n".to_vec());
    assert!(TodoNoOwnerRule.run(&fx.ctx()).is_empty());
}

#[test]
fn todo_no_owner_silent_when_owner_present_brackets() {
    let fx = Fixture::new().with_file("src/a.py", b"# TODO[alice]: rewrite\nx = 1\n".to_vec());
    assert!(TodoNoOwnerRule.run(&fx.ctx()).is_empty());
}

#[test]
fn todo_no_owner_skips_test_fixture() {
    let fx = Fixture::new().with_file("tests/a.py", b"# TODO: rewrite\nx = 1\n".to_vec());
    assert!(TodoNoOwnerRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_ten_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinFormattingPack)
        .expect("Family-26 formatting pack registers without error");
    assert_eq!(reg.rules().count(), 10);
    for slug in [
        "cc.fmt.trailing_whitespace",
        "cc.fmt.mixed_indentation",
        "cc.fmt.tab_in_python",
        "cc.fmt.crlf_line_endings",
        "cc.fmt.bom_present",
        "cc.fmt.no_final_newline",
        "cc.fmt.multiple_blank_lines",
        "cc.fmt.inconsistent_string_quotes",
        "cc.fmt.long_line",
        "cc.fmt.todo_no_owner",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
