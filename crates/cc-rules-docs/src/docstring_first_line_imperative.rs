//! `cc.docs.docstring_first_line_imperative` — Python docstring whose
//! first line opens with a non-imperative verb (e.g. "Returns the …",
//! "Computes the …", "Iterating …").
//!
//! Mirrors ruff `D401` (non-imperative-mood).
//!
//! Phase-10 detector: identical scan as
//! [`crate::docstring_first_line_period`]; once the first content line
//! is found, take its leading word and apply a heuristic — words ending
//! in `s` / `ed` / `ing` are flagged unless they appear in the
//! `IMPERATIVE_ALLOWLIST` (linking verbs / state verbs that are
//! grammatically imperative even though they end in `s`).
//!
//! Severity: `Nit`. Confidence 0.8 — heuristic, English-only, blind to
//! domain jargon.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, DocsFindingBlueprint,
};

/// Family-16 probe `cc.docs.docstring_first_line_imperative`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocstringFirstLineImperativeRule;

/// Verbs that grammatically end in `s` / `ed` / `ing` but are valid in
/// imperative-mood docstrings (linking verbs, state verbs, common
/// docstring-prefix verbs that mutate-the-thing).
const IMPERATIVE_ALLOWLIST: &[&str] = &[
    "is", "does", "has", "was", "as", "address", "access", "assess", "bias", "bless", "bus",
    "compress", "discuss", "dismiss", "express", "focus", "guess", "harness", "kiss", "miss",
    "pass", "press", "process", "release", "rinse", "stress", "sublease", "toss", "use", "witness",
];

const NON_IMPERATIVE_SUFFIXES: &[&str] = &["ing", "ed", "s"];

impl Rule for DocstringFirstLineImperativeRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.docstring_first_line_imperative"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "docstring first line should be in the imperative mood"
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
        let Some(first_content) = first_content_line_of_docstring(&lines, docstring_idx) else {
            continue;
        };
        if let Some(verb) = non_imperative_first_word(&first_content) {
            out.push(emit(path.clone(), docstring_idx + 1, &first_content, &verb));
        }
    }
}

fn is_def_or_class_header(trimmed: &str) -> bool {
    trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("class ")
}

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

/// Return the offending verb if the first word looks non-imperative.
fn non_imperative_first_word(line: &str) -> Option<String> {
    let first = line.split_whitespace().next()?;
    let cleaned: String = first.chars().take_while(|c| c.is_alphabetic()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let lower = cleaned.to_ascii_lowercase();
    if IMPERATIVE_ALLOWLIST.iter().any(|w| *w == lower) {
        return None;
    }
    if NON_IMPERATIVE_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        Some(cleaned)
    } else {
        None
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, verb: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.chars().take(180).collect();
    build_finding(DocsFindingBlueprint {
        rule_id: "cc.docs.docstring_first_line_imperative",
        severity: Severity::Nit,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("docstring opens with `{verb}` — prefer imperative mood"),
        explanation: format!(
            "Per PEP 257, a docstring's summary line should be a command \
             in the imperative mood (\"Return the result\", \"Compute the \
             total\"), not a description (\"Returns the result\", \
             \"Computes the total\"). The leading word `{verb}` reads as \
             a third-person description. Imperative summaries fit a \
             generated index — `help(func)` shows `Return the result.` \
             alongside `Send the email.` consistently."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rewrite the first word as an imperative verb: \
             `Returns` -> `Return`, `Computes` -> `Compute`, \
             `Iterating` -> `Iterate`. Mirrors ruff D401."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
