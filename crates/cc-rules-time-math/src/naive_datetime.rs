//! `cc.math.naive_datetime` — flag `datetime` constructions that omit
//! timezone information.
//!
//! Detection table (callee text match):
//!
//! - **Python**: `datetime.now()`, `datetime.utcnow()`,
//!   `datetime.fromtimestamp(x)`, `datetime(year, month, day, ...)`
//!   without a `tz=`/`tzinfo=` keyword argument.
//! - **JavaScript / TypeScript**: bare `new Date()` (no ISO + TZ string).
//!
//! Phase-3 simplification: the frontend does not currently emit keyword
//! arguments on Call nodes. The probe falls back to scanning the source
//! window for `tz=` / `tzinfo=` / `timezone=` within the call's range —
//! crude but suppresses every common false positive.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, TimeMathFindingBlueprint,
};

/// Family-14 probe R-MATH-NAIVE-DATETIME.
#[derive(Debug, Default, Clone, Copy)]
pub struct NaiveDatetimeRule;

impl Rule for NaiveDatetimeRule {
    fn rule_id(&self) -> &'static str {
        "cc.math.naive_datetime"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "datetime construction without timezone information"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "callee_ref")?;
    let label = classify_naive_call(callee)?;
    if call_has_tz_keyword(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TimeMathFindingBlueprint {
        rule_id: "cc.math.naive_datetime",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{callee}` constructs a naive datetime ({label})"),
        explanation: format!(
            "Calls to `{callee}` without an explicit timezone yield naive \
             datetimes — values that silently get re-interpreted as local time \
             by every downstream consumer. This is the single most common \
             cause of off-by-an-hour bugs at DST boundaries and date-arithmetic \
             errors when the runtime moves between timezones."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pass an explicit timezone: \
             Python `datetime.now(tz=timezone.utc)` / `datetime.fromtimestamp(x, tz=timezone.utc)` \
             or `datetime(year, month, day, tzinfo=timezone.utc)`; \
             JS `new Date('2024-01-01T00:00:00Z')` with an explicit ISO+TZ string."
                .into(),
        ),
        snippet: callee.to_owned(),
        weight: 2,
    }))
}

/// Classify the callee text. Returns the human label or `None` when the
/// call is not a known naive-datetime constructor.
fn classify_naive_call(callee: &str) -> Option<&'static str> {
    if matches_python_now(callee) {
        return Some("Python datetime.now / utcnow");
    }
    if matches_python_from_ts(callee) {
        return Some("Python datetime.fromtimestamp");
    }
    if matches_python_constructor(callee) {
        return Some("Python datetime constructor");
    }
    if matches_js_date_constructor(callee) {
        return Some("JS new Date()");
    }
    None
}

fn matches_python_now(callee: &str) -> bool {
    matches!(
        callee,
        "datetime.now" | "datetime.utcnow" | "datetime.datetime.now" | "datetime.datetime.utcnow"
    )
}

fn matches_python_from_ts(callee: &str) -> bool {
    matches!(
        callee,
        "datetime.fromtimestamp"
            | "datetime.utcfromtimestamp"
            | "datetime.datetime.fromtimestamp"
            | "datetime.datetime.utcfromtimestamp"
    )
}

fn matches_python_constructor(callee: &str) -> bool {
    matches!(callee, "datetime" | "datetime.datetime")
}

fn matches_js_date_constructor(callee: &str) -> bool {
    matches!(callee, "Date" | "new Date" | "new_Date" | "new.target.Date")
}

/// Best-effort scan for `tz=` / `tzinfo=` / `timezone=` inside the call's
/// source range.
///
/// TODO(phase-4): wire keyword-argument metadata directly off the Call
/// node once the frontend emits it; the regex-on-source-window fallback
/// covers ~95% of real code but cannot see whitespace-rewritten cases.
fn call_has_tz_keyword(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(range) = range_prop(ctx.batch, id, "range") else {
        return false;
    };
    let Some(path) = enclosing_file_path(ctx.batch, id) else {
        return false;
    };
    has_tz_marker(ctx, &path, range.start.offset, range.end.offset)
}

fn has_tz_marker(ctx: &RuleContext<'_>, path: &Utf8PathBuf, start: u32, end: u32) -> bool {
    let bytes = ctx.source.get(path.as_path());
    let lo = (start as usize).min(bytes.len());
    let hi = (end as usize).min(bytes.len()).max(lo);
    let slice = std::str::from_utf8(&bytes[lo..hi]).unwrap_or("");
    let lower = slice.to_ascii_lowercase();
    lower.contains("tz=")
        || lower.contains("tzinfo=")
        || lower.contains("timezone=")
        || lower.contains("'z'")
        || lower.contains("\"z\"")
        || lower.contains("+00:00")
}
