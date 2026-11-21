//! `cc.fmt.trailing_whitespace` — flag every line that ends with one
//! or more space/tab characters before the line terminator.
//!
//! Trailing whitespace is invisible to most editors but mutates diffs
//! the moment any tool normalises it. ruff `W291`, ESLint
//! `no-trailing-spaces`, gofumpt and rustfmt all reject it.
//!
//! Severity: [`Severity::Nit`]. Test fixtures are skipped.

use cc_finding::Category;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Family-26 probe R-FMT-TRAILING-WS.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrailingWhitespaceRule;

impl Rule for TrailingWhitespaceRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.trailing_whitespace"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.99)
    }
    fn description(&self) -> &'static str {
        "line ends with whitespace before the terminator"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for (idx, raw) in text.lines().enumerate() {
                if !ends_with_whitespace(raw) {
                    continue;
                }
                let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
                out.push(emit(path.clone(), lineno));
            }
        }
        out
    }
}

fn ends_with_whitespace(line: &str) -> bool {
    matches!(line.chars().last(), Some(' ' | '\t'))
}

fn emit(path: camino::Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path, lineno);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.trailing_whitespace",
        severity: Severity::Nit,
        confidence: Confidence::new(0.99),
        location,
        headline: format!("line {lineno} ends with trailing whitespace"),
        explanation: format!(
            "Line {lineno} terminates with one or more space/tab characters \
             before the newline. Trailing whitespace is invisible in most \
             editors but creates phantom diffs whenever a tool strips it."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Strip trailing whitespace via your editor's save hook or run \
             `sed -i 's/[ \\t]*$//' <file>` (POSIX) on the file."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
