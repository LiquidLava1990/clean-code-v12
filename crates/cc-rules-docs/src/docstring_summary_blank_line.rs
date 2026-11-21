//! `cc.docs.docstring_summary_blank_line` — multi-line Python docstring
//! whose second line is non-empty (no blank line between the summary
//! line and the body details).
//!
//! Mirrors ruff `D205` (blank-line-after-summary).
//!
//! Phase-10 detector: scan every `.py` file once. For each triple-quoted
//! docstring with two or more content lines, require a blank line
//! between the first and second non-empty lines. Single-line docstrings
//! are exempt.
//!
//! Severity: `Nit`. Confidence 0.9 — purely lexical, the only false
//! positive is unconventional Sphinx single-paragraph docstrings.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, DocsFindingBlueprint,
};

/// Family-16 probe `cc.docs.docstring_summary_blank_line`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocstringSummaryBlankLineRule;

impl Rule for DocstringSummaryBlankLineRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.docstring_summary_blank_line"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "multi-line docstring missing blank line between summary and body"
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
        if violates_summary_blank(&lines, docstring_idx) {
            out.push(emit(path.clone(), docstring_idx + 1, lines[docstring_idx]));
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

/// True iff the docstring opens with content on the first line and the
/// next non-blank line is a body line (not the closing triple-quote and
/// not blank).
fn violates_summary_blank(lines: &[&str], idx: usize) -> bool {
    let opener = lines.get(idx).copied().unwrap_or("");
    let trimmed = opener.trim_start();
    let Some(after) = strip_opener(trimmed) else {
        return false;
    };
    if after.contains("\"\"\"") || after.contains("'''") {
        // Single-line docstring like `"""text."""` — exempt.
        return false;
    }
    if after.trim().is_empty() {
        // Multi-line where summary lives on the *next* line — that
        // form is conventional (`"""` then text), require blank
        // between `next` and `next+1`.
        return summary_then_body_without_gap(lines, idx + 1);
    }
    // Summary on the opening line; check the immediate follower.
    let Some(next) = lines.get(idx + 1) else {
        return false;
    };
    let next_trimmed = next.trim();
    if next_trimmed.is_empty() {
        return false;
    }
    if next_trimmed.contains("\"\"\"") || next_trimmed.contains("'''") {
        return false;
    }
    true
}

fn strip_opener(trimmed: &str) -> Option<&str> {
    trimmed
        .strip_prefix("r\"\"\"")
        .or_else(|| trimmed.strip_prefix("r'''"))
        .or_else(|| trimmed.strip_prefix("\"\"\""))
        .or_else(|| trimmed.strip_prefix("'''"))
}

fn summary_then_body_without_gap(lines: &[&str], summary_idx: usize) -> bool {
    let Some(summary_line) = lines.get(summary_idx) else {
        return false;
    };
    if summary_line.trim().is_empty() {
        return false;
    }
    let Some(after) = lines.get(summary_idx + 1) else {
        return false;
    };
    let trimmed = after.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains("\"\"\"") || trimmed.contains("'''") {
        return false;
    }
    true
}

fn emit(path: Utf8PathBuf, line_no: usize, opener: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = opener.trim().chars().take(180).collect();
    build_finding(DocsFindingBlueprint {
        rule_id: "cc.docs.docstring_summary_blank_line",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "multi-line docstring missing blank line after summary".into(),
        explanation: "Per PEP 257, a multi-line docstring should separate \
             its one-line summary from the rest of the prose with a single \
             blank line. Tools that surface only the summary (Sphinx \
             autosummary, IDE hover preview, `help(...)`) rely on the \
             blank line to know where to cut. Without it, the second line \
             gets concatenated onto the headline."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Insert a blank line between the summary line and the rest of \
             the docstring. Mirrors ruff D205 autofix."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
