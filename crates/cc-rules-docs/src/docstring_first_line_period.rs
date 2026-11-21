//! `cc.docs.docstring_first_line_period` — Python docstring whose first
//! line does not end with `.`/`!`/`?`.
//!
//! Mirrors ruff `D400` (ends-in-period).
//!
//! Phase-10 detector: scan every `.py` file once. For each triple-quoted
//! docstring (the first string literal after a `def`/`class`/`async def`
//! line), inspect the first non-empty content line. If that line lacks
//! a sentence-ending punctuation mark, flag.
//!
//! Severity: `Nit` — a missing period is a presentation polish item,
//! never a correctness issue. Confidence 0.95 because the pattern is
//! purely lexical with no false-positive surface beyond the known
//! exemptions handled below.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, DocsFindingBlueprint,
};

/// Family-16 probe `cc.docs.docstring_first_line_period`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocstringFirstLinePeriodRule;

const SENTENCE_TERMINATORS: &[char] = &['.', '!', '?', ':'];

impl Rule for DocstringFirstLinePeriodRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.docstring_first_line_period"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "docstring first line should end with a period"
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
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
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
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !is_def_or_class_header(trimmed) {
            continue;
        }
        let Some(docstring_idx) = next_docstring_line(&lines, idx + 1) else {
            continue;
        };
        if let Some(first_content) = first_content_line_of_docstring(&lines, docstring_idx) {
            if !ends_in_sentence_terminator(&first_content) {
                out.push(emit(path.clone(), docstring_idx + 1, &first_content));
            }
        }
    }
}

fn is_def_or_class_header(trimmed: &str) -> bool {
    trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("class ")
}

/// From `start_idx`, skip blank/comment lines until we land on a triple-
/// quoted docstring opening line. Returns its index when found.
fn next_docstring_line(lines: &[&str], start_idx: usize) -> Option<usize> {
    for (offset, line) in lines.iter().enumerate().skip(start_idx) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("'''")
            || trimmed.starts_with("r\"\"\"")
            || trimmed.starts_with("r'''")
        {
            return Some(offset);
        }
        return None;
    }
    None
}

/// Extract the first non-empty content line of a triple-quoted
/// docstring. Handles single-line `"""text."""` and multi-line cases.
fn first_content_line_of_docstring(lines: &[&str], idx: usize) -> Option<String> {
    let opener = lines.get(idx)?;
    let trimmed = opener.trim_start();
    let after = trimmed
        .strip_prefix("r\"\"\"")
        .or_else(|| trimmed.strip_prefix("r'''"))
        .or_else(|| trimmed.strip_prefix("\"\"\""))
        .or_else(|| trimmed.strip_prefix("'''"))?;
    let head = strip_trailing_quotes(after).trim();
    if !head.is_empty() {
        return Some(head.to_owned());
    }
    for follow in lines.iter().skip(idx + 1) {
        let t = follow.trim();
        if t.is_empty() {
            continue;
        }
        return Some(strip_trailing_quotes(t).trim().to_owned());
    }
    None
}

fn strip_trailing_quotes(s: &str) -> &str {
    s.strip_suffix("\"\"\"")
        .or_else(|| s.strip_suffix("'''"))
        .unwrap_or(s)
}

fn ends_in_sentence_terminator(line: &str) -> bool {
    let trimmed = line.trim_end_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    if trimmed.is_empty() {
        return true;
    }
    trimmed.ends_with(SENTENCE_TERMINATORS)
}

fn emit(path: Utf8PathBuf, line_no: usize, first_line: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = first_line.chars().take(180).collect();
    build_finding(DocsFindingBlueprint {
        rule_id: "cc.docs.docstring_first_line_period",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: "docstring first line missing terminator (`.` / `!` / `?`)".into(),
        explanation: "Per PEP 257, a docstring's summary line should be a \
             complete sentence ending with a period. Tools that surface \
             docstrings (Sphinx, IDE hover, `help()`) render the first \
             line as the symbol's headline; a trailing period keeps it \
             readable when concatenated with downstream prose."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add a `.` (or `!` / `?` when the summary is exclamatory or \
             interrogative) to the end of the first line. Mirrors ruff \
             D400 autofix."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
