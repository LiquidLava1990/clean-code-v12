//! `cc.test.pt_missing_test_classname_prefix` — class declared in a
//! pytest test file (`test_*.py` / `*_test.py` / under `tests/`) whose
//! name does not start with `Test`. Pytest test-discovery only picks up
//! classes named `Test...`, so a class named e.g. `LoginCases` will be
//! skipped silently and the would-be tests inside never run.
//!
//! Mirrors ruff PT018 / PT021 family. The motivation: silent test
//! skips. A class containing `def test_*` methods that pytest does not
//! discover is the worst kind of test rot — green pipeline, zero
//! coverage.
//!
//! Phase-10 source-byte detector: `.py` files only, scan every line for
//! `class NAME(...):` or `class NAME:` whose first character is not a
//! capital `T` followed by `est` (or `_`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.pt_missing_test_classname_prefix`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtMissingTestClassnamePrefixRule;

impl Rule for PtMissingTestClassnamePrefixRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.pt_missing_test_classname_prefix"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test-file class missing `Test` prefix — pytest discovery skips it"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if !is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let Some(class_name) = parse_top_level_class(line) else {
            continue;
        };
        if class_name.starts_with("Test") {
            continue;
        }
        if class_name.starts_with('_') {
            // Private helper class — pytest skips intentionally.
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, &class_name));
    }
}

/// Parse `class NAME(...):` or `class NAME:` at column 0. Returns the
/// class name. Returns `None` for indented (nested) classes — only
/// top-level classes drive pytest discovery.
fn parse_top_level_class(line: &str) -> Option<String> {
    if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
        return None;
    }
    let after = line.strip_prefix("class ")?;
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let next = after.as_bytes().get(name.len()).copied();
    match next {
        Some(b'(') | Some(b':') | Some(b' ') | Some(b'\t') => Some(name),
        _ => None,
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, class_name: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(class_name.to_owned()),
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let suggested = format!("Test{class_name}");
    build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.pt_missing_test_classname_prefix",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("test-file class `{class_name}` is missing the `Test` prefix"),
        explanation: format!(
            "Pytest only discovers classes whose name starts with \
             `Test`. `{class_name}` lives in a test file but pytest \
             will skip it during collection — every `def test_*` \
             method inside is silently never run. The test file looks \
             green even though no assertions execute."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename `{class_name}` to `{suggested}` (or any name \
             starting with `Test`). If the class is intentionally a \
             helper rather than a test container, prefix the name with \
             `_` to mark it private and document the intent."
        )),
        snippet,
        weight: 1,
    })
}
