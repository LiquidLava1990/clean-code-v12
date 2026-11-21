//! `cc.math.dst_unsafe` — flag local-time arithmetic likely to break
//! across DST boundaries.
//!
//! Phase-3 simplification: detect any [`NodeKind::Call`] whose callee
//! creates a day-granularity duration (`timedelta(days=...)`,
//! `chrono::Duration::days(...)`, `time.Add(24*time.Hour)`) and whose
//! enclosing function body subsequently calls a wall-clock accessor
//! (`.date()` / `.day()` / `.weekday()` / `.hour()` / `format` /
//! `.strftime`).
//!
//! The two-step "duration creation + wall-clock read in same body"
//! signal is conservative — it only fires when both sides are present —
//! but it catches the canonical "add 24 hours then format the date"
//! bug that breaks once a year on the local DST boundary.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, TimeMathFindingBlueprint,
};

/// Family-14 probe R-MATH-DST-UNSAFE.
#[derive(Debug, Default, Clone, Copy)]
pub struct DstUnsafeRule;

impl Rule for DstUnsafeRule {
    fn rule_id(&self) -> &'static str {
        "cc.math.dst_unsafe"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "day-granularity duration arithmetic followed by wall-clock read"
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
    if !is_day_granularity_duration(callee) {
        return None;
    }
    let scope = enclosing_function_or_file(ctx, id)?;
    if !scope_calls_wall_clock(ctx, scope, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TimeMathFindingBlueprint {
        rule_id: "cc.math.dst_unsafe",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{callee}` adds days then code reads a wall-clock field"),
        explanation: format!(
            "Adding `days=N` (or `24 * Hour`) then asking for the calendar date / \
             hour / weekday breaks twice a year on every DST boundary: 24 hours \
             ahead of midnight is *not* the next midnight when the clocks shift. \
             `{callee}` creates a day-granularity duration and a wall-clock \
             accessor runs later in the same body."
        ),
        remediation: Remediation::SuggestedRewrite(
            "If you want 'the same wall-clock time tomorrow', use a calendar-aware \
             API: Python `dt + relativedelta(days=1)` with a tz-aware datetime, \
             Rust `chrono::DateTime::with_timezone` + `+ Duration::days(1)` on a \
             `DateTime<Tz>`, Go `time.Date` reconstruction. If you really want \
             '24 hours later', say so in a comment so this rule can be suppressed."
                .into(),
        ),
        snippet: callee.to_owned(),
        weight: 2,
    }))
}

/// True iff `callee` constructs a day-granularity (or 24-hour-equivalent)
/// duration in any of the four supported languages.
fn is_day_granularity_duration(callee: &str) -> bool {
    if matches_python_timedelta(callee) {
        return true;
    }
    matches_rust_duration_days(callee) || matches_go_duration(callee)
}

fn matches_python_timedelta(callee: &str) -> bool {
    matches!(
        callee,
        "timedelta" | "datetime.timedelta" | "datetime.datetime.timedelta"
    )
}

fn matches_rust_duration_days(callee: &str) -> bool {
    matches!(
        callee,
        "chrono::Duration::days"
            | "Duration::days"
            | "chrono::Duration::hours"
            | "Duration::hours"
            | "std::time::Duration::from_secs"
    )
}

fn matches_go_duration(callee: &str) -> bool {
    matches!(callee, "time.Hour" | "time.Add" | "time.AddDate")
}

/// Walk up to the enclosing function (or file root). The returned id is
/// the scope whose descendants we search for wall-clock reads.
fn enclosing_function_or_file(ctx: &RuleContext<'_>, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        let parent = ast_parent(ctx.batch, id)?;
        match node_kind(ctx.batch, parent) {
            Some(NodeKind::Function | NodeKind::Method | NodeKind::File) => return Some(parent),
            _ => id = parent,
        }
    }
    None
}

/// True iff any descendant Call inside `scope` (other than `excluded`)
/// is a wall-clock accessor.
fn scope_calls_wall_clock(ctx: &RuleContext<'_>, scope: NodeId, excluded: NodeId) -> bool {
    let mut stack: Vec<NodeId> = ast_children(ctx.batch, scope).collect();
    while let Some(id) = stack.pop() {
        for child in ast_children(ctx.batch, id) {
            stack.push(child);
        }
        if id == excluded {
            continue;
        }
        if node_kind(ctx.batch, id) != Some(NodeKind::Call) {
            continue;
        }
        if let Some(callee) = string_prop(ctx.batch, id, "callee_ref") {
            if is_wall_clock_accessor(callee) {
                return true;
            }
        }
    }
    false
}

/// Closed list of wall-clock-bearing accessors that, when paired with
/// day-granularity arithmetic, surface DST bugs.
fn is_wall_clock_accessor(callee: &str) -> bool {
    matches!(
        callee,
        "date"
            | "day"
            | "weekday"
            | "hour"
            | "format"
            | "strftime"
            | "isoformat"
            | "toLocaleDateString"
            | "toLocaleString"
            | "Format"
            | "DateTime.Format"
            | "Date.toISOString"
    ) || callee.ends_with(".date")
        || callee.ends_with(".day")
        || callee.ends_with(".weekday")
        || callee.ends_with(".hour")
        || callee.ends_with(".strftime")
        || callee.ends_with(".format")
}
