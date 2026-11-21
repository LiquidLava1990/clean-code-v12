//! `cc.fmt.mixed_indentation` — flag a file that contains BOTH
//! tab-indented and space-indented lines.
//!
//! Mixing the two breaks alignment in any editor whose tab width
//! differs from the original author's. ruff `W191` / `E101`, gofumpt,
//! and most formatters fail the file outright. The probe skips lines
//! inside obvious string literals (`"""..."""` / `'''...'''`) at a
//! crude level — enough to suppress false positives in Python
//! docstrings without dragging a full lexer into the pack.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Family-26 probe R-FMT-MIXED-INDENT.
#[derive(Debug, Default, Clone, Copy)]
pub struct MixedIndentationRule;

impl Rule for MixedIndentationRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.mixed_indentation"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "file mixes tab- and space-indented lines"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            let (tabs, spaces) = scan_indentation(text);
            if tabs > 0 && spaces > 0 {
                out.push(emit(path, tabs, spaces));
            }
        }
        out
    }
}

/// Returns `(tab_indented_lines, space_indented_lines)` outside of
/// triple-quoted Python heredocs.
fn scan_indentation(text: &str) -> (u32, u32) {
    let mut tabs: u32 = 0;
    let mut spaces: u32 = 0;
    let mut in_heredoc = false;
    for raw in text.lines() {
        if has_heredoc_marker(raw) {
            in_heredoc = !in_heredoc;
            continue;
        }
        if in_heredoc {
            continue;
        }
        match raw.chars().next() {
            Some('\t') => tabs = tabs.saturating_add(1),
            Some(' ') if raw.len() >= 2 => spaces = spaces.saturating_add(1),
            _ => {}
        }
    }
    (tabs, spaces)
}

fn has_heredoc_marker(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''")
}

fn emit(path: camino::Utf8PathBuf, tabs: u32, spaces: u32) -> Finding {
    let location = location_for_file(path, 1);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.mixed_indentation",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "file mixes indentation styles ({tabs} tab-indented, {spaces} space-indented lines)"
        ),
        explanation: String::from(
            "The file uses both tab indentation and space indentation on \
             different lines. Editors with a tab width other than the \
             original author's render the file misaligned, and most \
             auto-formatters reject the input outright.",
        ),
        remediation: Remediation::SuggestedRewrite(
            "Convert every line to one indentation style (the project's \
             dominant style; if unsure, use 4 spaces)."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
