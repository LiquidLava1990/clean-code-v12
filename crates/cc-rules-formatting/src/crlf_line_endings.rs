//! `cc.fmt.crlf_line_endings` — flag source files that use `\r\n`
//! line endings.
//!
//! Heuristic: any `\r\n` in `*.py` / `*.rs` / `*.go` / `*.ts` / `*.tsx`
//! / `*.js` / `*.jsx` is a finding. To avoid the Windows-checkout
//! pathological case where every file fires, the rule downgrades to a
//! single per-repo "many files use CRLF" finding when the count
//! exceeds [`MANY_FILES_THRESHOLD`].

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, has_source_extension, location_for_file,
    FormattingFindingBlueprint,
};

/// Above this threshold the per-file findings collapse to a single
/// repo-wide aggregate. Picked so that a Windows clone with global
/// CRLF normalisation does not produce a wall of noise.
pub const MANY_FILES_THRESHOLD: usize = 100;

/// Family-26 probe R-FMT-CRLF.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrlfLineEndingsRule;

impl Rule for CrlfLineEndingsRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.crlf_line_endings"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "source file uses CRLF (\\r\\n) line endings"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let hits = collect_crlf_hits(ctx);
        if hits.len() > MANY_FILES_THRESHOLD {
            return vec![emit_aggregate(hits.len())];
        }
        hits.into_iter().map(emit_per_file).collect()
    }
}

fn collect_crlf_hits(ctx: &RuleContext<'_>) -> Vec<Utf8PathBuf> {
    let mut hits = Vec::new();
    for (path, bytes) in each_source_file(ctx) {
        if !has_source_extension(&path) {
            continue;
        }
        if bytes.windows(2).any(|w| w == b"\r\n") {
            hits.push(path);
        }
    }
    hits
}

fn emit_per_file(path: Utf8PathBuf) -> Finding {
    crlf_finding(
        path.clone(),
        format!("{path} uses CRLF line endings"),
        String::from(
            "The file contains carriage-return + line-feed (\\r\\n) line \
             terminators. Mixed line endings cause noisy diffs across \
             contributors on different platforms and break tools that \
             expect LF-only input (rustfmt, gofumpt, many shell scripts).",
        ),
        "Convert with `dos2unix <file>` or set `* text=auto eol=lf` in \
         `.gitattributes` and run `git add --renormalize .`.",
    )
}

fn emit_aggregate(count: usize) -> Finding {
    crlf_finding(
        Utf8PathBuf::from("."),
        format!("{count} source files use CRLF line endings"),
        format!(
            "{count} source files in this repo use CRLF (\\r\\n) line \
             endings. The probe collapsed per-file findings to this \
             single aggregate because the count exceeded \
             {MANY_FILES_THRESHOLD} — likely a Windows checkout with \
             auto-CRLF normalisation rather than per-file drift."
        ),
        "Either accept CRLF as the project policy by adding \
         `* text=auto eol=crlf` to `.gitattributes`, or normalise to \
         LF with `* text=auto eol=lf` plus `git add --renormalize .`.",
    )
}

/// Shared builder for both the per-file and aggregate variants. The
/// rule-id / severity / confidence / weight are policy-fixed; only the
/// location, headline, explanation, and remediation change.
fn crlf_finding(
    path: Utf8PathBuf,
    headline: String,
    explanation: String,
    remediation_text: &'static str,
) -> Finding {
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.crlf_line_endings",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location: location_for_file(path, 1),
        headline,
        explanation,
        remediation: Remediation::SuggestedRewrite(remediation_text.into()),
        snippet: String::new(),
        weight: 0,
    })
}
