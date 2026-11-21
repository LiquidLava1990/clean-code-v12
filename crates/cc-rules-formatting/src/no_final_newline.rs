//! `cc.fmt.no_final_newline` — flag a file that does not end with a
//! newline character.
//!
//! POSIX defines a "line" as a sequence of zero or more non-newline
//! characters terminated by `\n`; a file that ends mid-line confuses
//! `cat`, breaks the last line of `git diff`, and trips most format
//! checkers (gofumpt, rustfmt, ruff `W292`, ESLint `eol-last`).

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Family-26 probe R-FMT-NO-FINAL-NL.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFinalNewlineRule;

impl Rule for NoFinalNewlineRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.no_final_newline"
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
        "file does not end with a newline"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            if bytes.is_empty() {
                continue;
            }
            if bytes.last().copied() == Some(b'\n') {
                continue;
            }
            out.push(emit(path));
        }
        out
    }
}

fn emit(path: camino::Utf8PathBuf) -> Finding {
    let location = location_for_file(path, 1);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.no_final_newline",
        severity: Severity::Nit,
        confidence: Confidence::new(0.99),
        location,
        headline: String::from("file does not end with a newline"),
        explanation: String::from(
            "POSIX requires every line to end with `\\n`. A file with \
             no terminating newline truncates in `cat`, garbles the \
             last hunk of `git diff`, and is rejected by most modern \
             formatters (rustfmt, gofumpt, black, ruff W292).",
        ),
        remediation: Remediation::SuggestedRewrite(
            "Append a single newline to the end of the file.".into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
