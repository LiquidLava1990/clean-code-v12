//! `cc.fmt.long_line` — flag any line longer than
//! [`DEFAULT_MAX_LINE_LEN`] characters.
//!
//! The threshold is configurable via `RuleConfig::options["max_line_len"]`
//! (Phase-7 wiring); for now, a hardcoded default. Lines containing
//! URLs / file URIs / `data:` URIs are skipped — the user cannot
//! reasonably break them.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, looks_like_url, FormattingFindingBlueprint,
};

/// Default maximum line length, in characters. Aligned with black /
/// ruff / rustfmt defaults (rustfmt uses 100; black uses 88; 120 is
/// the conventional ceiling for repos that don't pin a stricter
/// formatter).
pub const DEFAULT_MAX_LINE_LEN: usize = 120;

/// Family-26 probe R-FMT-LONG-LINE.
#[derive(Debug, Default, Clone, Copy)]
pub struct LongLineRule;

impl Rule for LongLineRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.long_line"
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
        "line exceeds the configured maximum length"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for (idx, raw) in text.lines().enumerate() {
                if !is_too_long(raw) {
                    continue;
                }
                let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
                let len = raw.chars().count();
                out.push(emit(path.clone(), lineno, len));
            }
        }
        out
    }
}

fn is_too_long(line: &str) -> bool {
    if looks_like_url(line) {
        return false;
    }
    line.chars().count() > DEFAULT_MAX_LINE_LEN
}

fn emit(path: camino::Utf8PathBuf, lineno: u32, len: usize) -> Finding {
    let location = location_for_file(path, lineno);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.long_line",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("line {lineno} is {len} characters (max {DEFAULT_MAX_LINE_LEN})"),
        explanation: format!(
            "Line {lineno} is {len} characters wide; the configured \
             maximum is {DEFAULT_MAX_LINE_LEN}. Long lines hurt \
             readability in side-by-side diffs and break the standard \
             `git log -p` 80-column terminal display."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Break the expression onto multiple lines or run an auto-formatter \
             (black / rustfmt / gofumpt / prettier) configured to the project's \
             ceiling."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
