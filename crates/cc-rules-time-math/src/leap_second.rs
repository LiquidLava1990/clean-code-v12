//! `cc.math.leap_second` — flag timestamp-delta-divided-by-seconds-per-unit.
//!
//! Heuristic: scan source lines for the textual pattern
//! `( <expr> - <expr> ) / <SECONDS_PER_UNIT>` where `SECONDS_PER_UNIT`
//! is one of the canonical constants:
//!
//! | constant | unit |
//! |----------|------|
//! | `86400`  | days |
//! | `3600`   | hours |
//! | `60`     | minutes |
//! | `604800` | weeks |
//! | `86_400` / `3_600` (Rust underscore numerals) | same as above |
//!
//! Severity is intentionally **Nit** — the rule fires rarely (real bug,
//! but advisory) and primarily exists to remind authors that POSIX
//! timestamp deltas are not exact across leap seconds.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, TimeMathFindingBlueprint,
};

/// Family-14 probe R-MATH-LEAP-SECOND.
#[derive(Debug, Default, Clone, Copy)]
pub struct LeapSecondRule;

impl Rule for LeapSecondRule {
    fn rule_id(&self) -> &'static str {
        "cc.math.leap_second"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "timestamp delta divided by seconds-per-unit assumes exact seconds"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            if let Some(mut produced) = scan_file(ctx, node.id) {
                out.append(&mut produced);
            }
        }
        out
    }
}

/// Scan one file's raw source for the leap-second-unsafe pattern.
fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId) -> Option<Vec<Finding>> {
    let path = string_prop(ctx.batch, file_id, "path").map(Utf8PathBuf::from)?;
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(divisor) = leap_unsafe_divisor(line) {
            if let Some(finding) = emit(ctx, file_id, line, divisor) {
                out.push(finding);
            }
        }
    }
    Some(out)
}

/// Return the matched divisor when the line looks like
/// `(<a> - <b>) / <SECONDS_PER_UNIT>`.
fn leap_unsafe_divisor(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    if !line.contains('-') || !line.contains('/') {
        return None;
    }
    if !looks_like_subtraction_then_divide(line) {
        return None;
    }
    DIVISOR_TABLE
        .iter()
        .copied()
        .find(|needle| line_contains_divisor(line, needle))
}

/// Closed list of seconds-per-unit divisors we treat as leap-unsafe.
const DIVISOR_TABLE: &[&str] = &[
    "86400", "86_400", "604800", "604_800", "3600", "3_600", "60.0", "86400.0",
];

/// True iff the line contains `... - ... / DIVISOR` in roughly that
/// order. Crude — but the false-positive rate is acceptable for a Nit.
fn looks_like_subtraction_then_divide(line: &str) -> bool {
    let Some(minus) = line.find('-') else {
        return false;
    };
    let Some(slash) = line.find('/') else {
        return false;
    };
    minus < slash
}

/// Match `divisor` only when surrounded by non-digit / non-underscore
/// characters so `860` doesn't trigger on `8600`.
fn line_contains_divisor(line: &str, divisor: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(divisor) {
        let abs = start + pos;
        let before_ok = abs == 0
            || !line.as_bytes()[abs - 1].is_ascii_alphanumeric()
                && line.as_bytes()[abs - 1] != b'_';
        let after = abs + divisor.len();
        let after_ok = after >= line.len()
            || !line.as_bytes()[after].is_ascii_alphanumeric()
                && line.as_bytes()[after] != b'_'
                && line.as_bytes()[after] != b'.';
        if before_ok && after_ok {
            return true;
        }
        start = abs + divisor.len();
    }
    false
}

fn emit(ctx: &RuleContext<'_>, file_id: NodeId, line: &str, divisor: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, file_id)?;
    let location = location_from_node(ctx.batch, file_id, path);
    Some(build_finding(TimeMathFindingBlueprint {
        rule_id: "cc.math.leap_second",
        category: Category::Bug,
        severity: Severity::Nit,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("timestamp delta divided by `{divisor}` assumes exact seconds-per-unit"),
        explanation: format!(
            "POSIX timestamps elide leap seconds, so `(end - start) / {divisor}` \
             can be wrong by one second per leap event for long intervals. The \
             arithmetic is fine for casual UI but breaks scheduling, billing, \
             and astronomy. Line: `{}`.",
            line.trim()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use a calendar-aware library: Python `(end - start).total_seconds()` \
             on tz-aware datetimes, Rust `chrono::Duration::num_days`, Go \
             `end.Sub(start).Hours() / 24`. For audit-grade accuracy use TAI / \
             monotonic clocks; for scheduling, use a calendar API."
                .into(),
        ),
        snippet: line.trim().to_owned(),
        weight: 1,
    }))
}
