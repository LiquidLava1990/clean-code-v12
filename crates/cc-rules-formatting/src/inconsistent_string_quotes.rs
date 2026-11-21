//! `cc.fmt.inconsistent_string_quotes` — flag a Python / JS / TS file
//! that uses both single- and double-quoted string literals.
//!
//! Heuristic: count occurrences of `'` and `"` in non-comment source
//! bytes; if the minority exceeds 5% of the total AND the total is
//! greater than [`MIN_TOTAL_QUOTES`], flag the file. Skips test
//! fixtures and any file whose extension is not Python / JS / TS.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Below this many total quote characters, the file is too small to
/// reach a confident verdict.
pub const MIN_TOTAL_QUOTES: u32 = 20;

/// Minority share above which the rule fires (5%).
pub const MINORITY_THRESHOLD: f64 = 0.05;

/// Family-26 probe R-FMT-INCONSISTENT-QUOTES.
#[derive(Debug, Default, Clone, Copy)]
pub struct InconsistentStringQuotesRule;

impl Rule for InconsistentStringQuotesRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.inconsistent_string_quotes"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "Python/JS/TS file mixes single- and double-quoted strings"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            if !is_quote_sensitive_extension(&path) {
                continue;
            }
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            let counts = count_quotes(text);
            if let Some((majority, minority)) = should_flag(counts) {
                out.push(emit(path, majority, minority));
            }
        }
        out
    }
}

fn is_quote_sensitive_extension(path: &camino::Utf8PathBuf) -> bool {
    matches!(
        path.extension(),
        Some("py" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
    )
}

#[derive(Debug, Clone, Copy)]
struct QuoteCounts {
    single: u32,
    double: u32,
}

/// Count single- and double-quote characters outside of comments.
/// Crude — comment detection only handles single-line `//` and `#`
/// prefixes; that suffices for the 5% threshold.
fn count_quotes(text: &str) -> QuoteCounts {
    let mut single: u32 = 0;
    let mut double: u32 = 0;
    for raw in text.lines() {
        let code = strip_line_comment(raw);
        for byte in code.bytes() {
            match byte {
                b'\'' => single = single.saturating_add(1),
                b'"' => double = double.saturating_add(1),
                _ => {}
            }
        }
    }
    QuoteCounts { single, double }
}

fn strip_line_comment(line: &str) -> &str {
    if let Some(idx) = line.find("//") {
        return &line[..idx];
    }
    if let Some(idx) = line.find('#') {
        return &line[..idx];
    }
    line
}

/// Return `(majority_label, minority_count)` when the file should be
/// flagged, else `None`.
fn should_flag(counts: QuoteCounts) -> Option<(&'static str, u32)> {
    let total = counts.single.saturating_add(counts.double);
    if total < MIN_TOTAL_QUOTES {
        return None;
    }
    let (majority_label, majority, minority) = if counts.single >= counts.double {
        ("single", counts.single, counts.double)
    } else {
        ("double", counts.double, counts.single)
    };
    let share = f64::from(minority) / f64::from(total.max(1));
    if share > MINORITY_THRESHOLD && minority > 0 && majority > 0 {
        Some((majority_label, minority))
    } else {
        None
    }
}

fn emit(path: camino::Utf8PathBuf, majority: &'static str, minority: u32) -> Finding {
    let location = location_for_file(path, 1);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.inconsistent_string_quotes",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!(
            "file mixes string-quote styles (majority: {majority}; minority count: {minority})"
        ),
        explanation: format!(
            "The file uses {majority} as the dominant quote style but \
             {minority} non-comment occurrences of the other style \
             remain. Black, ruff `Q*`, ESLint `quotes`, and prettier \
             all enforce a single style per file."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Run black / ruff format / prettier with quote normalisation \
             enabled, or convert the minority instances by hand."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
