//! `cc.fmt.multiple_blank_lines` — flag a file that contains a run of
//! more than two consecutive blank lines.
//!
//! Most formatters cap consecutive blanks at two (PEP 8, gofumpt,
//! rustfmt, ESLint `no-multiple-empty-lines`). Three+ blanks in a
//! row is dead vertical whitespace.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Maximum consecutive blank lines tolerated before a finding fires.
pub const MAX_BLANK_RUN: u32 = 2;

/// Family-26 probe R-FMT-MULTI-BLANK.
#[derive(Debug, Default, Clone, Copy)]
pub struct MultipleBlankLinesRule;

impl Rule for MultipleBlankLinesRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.multiple_blank_lines"
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
        "more than two consecutive blank lines"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for lineno in find_excess_blank_runs(text) {
                out.push(emit(path.clone(), lineno));
            }
        }
        out
    }
}

/// Return the 1-based line numbers of the first blank line in every
/// run of length > [`MAX_BLANK_RUN`].
fn find_excess_blank_runs(text: &str) -> Vec<u32> {
    let mut hits = Vec::new();
    let mut run: u32 = 0;
    let mut run_start: u32 = 0;
    let mut already_reported = false;
    for (idx, raw) in text.lines().enumerate() {
        let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        if raw.trim().is_empty() {
            if run == 0 {
                run_start = lineno;
                already_reported = false;
            }
            run = run.saturating_add(1);
            if run > MAX_BLANK_RUN && !already_reported {
                hits.push(run_start);
                already_reported = true;
            }
        } else {
            run = 0;
        }
    }
    hits
}

fn emit(path: camino::Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path, lineno);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.multiple_blank_lines",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "{} consecutive blank lines starting at line {}",
            "more than two", lineno
        ),
        explanation: format!(
            "A run of more than {MAX_BLANK_RUN} consecutive blank lines \
             begins at line {lineno}. Most formatters (PEP 8, gofumpt, \
             rustfmt, ESLint) cap consecutive blanks at two; longer \
             runs are dead vertical whitespace."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Collapse the run to at most two consecutive blank lines.".into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
