//! `cc.bug.time_bomb` — hardcoded date strings + Y2038 risks.
//!
//! Three signals fire this rule:
//!
//! - Literal strings matching `YYYY-MM-DD` outside test files.
//! - Integer literals `2147483647` / `0x7FFFFFFF` (`i32::MAX`) used in
//!   anything time-shaped (variable name contains `time`, `timestamp`,
//!   `epoch`, `expires`, `deadline`).
//! - Calls to `datetime.utcnow()` (Python: deprecated, returns naive).
//!
//! The probe walks `NodeKind::Literal` and `NodeKind::Call` nodes
//! independently; each signal is reported at `Severity::Required`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, int_prop, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-TIME-BOMB.
#[derive(Debug, Default, Clone, Copy)]
pub struct TimeBombRule;

const TIME_NAME_HINTS: &[&str] = &["time", "timestamp", "epoch", "expires", "deadline"];

impl Rule for TimeBombRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.time_bomb"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "hardcoded date / Y2038 timestamp / deprecated naive utcnow()"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Literal) {
            if let Some(finding) = check_literal(ctx, node.id) {
                out.push(finding);
            }
        }
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_literal(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if let Some(value) = string_prop(ctx.batch, id, "value") {
        if looks_like_iso_date(value) {
            return Some(emit_iso(ctx, id, path, value));
        }
    }
    if let Some(value) = int_prop(ctx.batch, id, "value") {
        if value == 2_147_483_647 && context_is_time_shaped(ctx, id) {
            return Some(emit_y2038(ctx, id, path));
        }
    }
    None
}

fn looks_like_iso_date(s: &str) -> bool {
    if s.len() < 10 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn context_is_time_shaped(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, id) else {
        return false;
    };
    let candidates = [
        string_prop(ctx.batch, parent, "target"),
        string_prop(ctx.batch, parent, "name"),
    ];
    candidates.iter().flatten().any(|name| {
        let lower = name.to_ascii_lowercase();
        TIME_NAME_HINTS.iter().any(|hint| lower.contains(hint))
    })
}

/// Inputs that vary per time-bomb signal — everything else (rule_id,
/// severity baseline) is shared via [`build_time_bomb`].
struct TimeBombSignal {
    confidence: f32,
    headline: String,
    explanation: String,
    rewrite: String,
    snippet: String,
    weight: u32,
}

fn build_time_bomb(
    ctx: &RuleContext<'_>,
    id: NodeId,
    path: camino::Utf8PathBuf,
    signal: TimeBombSignal,
) -> Finding {
    let location = location_from_node(ctx.batch, id, path);
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.time_bomb",
        severity: Severity::Required,
        confidence: Confidence::new(signal.confidence),
        location,
        headline: signal.headline,
        explanation: signal.explanation,
        remediation: Remediation::SuggestedRewrite(signal.rewrite),
        snippet: signal.snippet,
        weight: signal.weight,
    })
}

fn emit_iso(ctx: &RuleContext<'_>, id: NodeId, path: camino::Utf8PathBuf, value: &str) -> Finding {
    build_time_bomb(
        ctx,
        id,
        path,
        TimeBombSignal {
            confidence: 0.75,
            headline: format!("hardcoded date string `{value}` will silently expire"),
            explanation: format!(
                "Literal date strings (`{value}`) baked into source code create \
                 time bombs — the calendar moves on, the constant doesn't. The \
                 code keeps compiling but its semantics drift the moment the \
                 real date passes the literal."
            ),
            rewrite: "Move the date into config / a feature flag, derive it from \
                 `today()` / `now()`, or assert at build time that the date is \
                 in the future."
                .into(),
            snippet: value.to_owned(),
            weight: 2,
        },
    )
}

fn emit_y2038(ctx: &RuleContext<'_>, id: NodeId, path: camino::Utf8PathBuf) -> Finding {
    build_time_bomb(
        ctx,
        id,
        path,
        TimeBombSignal {
            confidence: 0.85,
            headline: "32-bit-max constant used as a timestamp / deadline".into(),
            explanation: "`2147483647` (`0x7FFFFFFF`) is `i32::MAX` — using it \
                 as a timestamp means the value rolls over on 2038-01-19. \
                 Always use 64-bit time."
                .into(),
            rewrite: "Use `i64::MAX` / `u64::MAX` for sentinel deadlines, or store \
                 the timestamp in a 64-bit type from the start."
                .into(),
            snippet: "2147483647".into(),
            weight: 3,
        },
    )
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    if !(text.contains("datetime.utcnow") || text.ends_with(".utcnow()")) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.time_bomb",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "`datetime.utcnow()` is deprecated and returns a naive datetime".into(),
        explanation: "`utcnow()` returns a *naive* datetime — no tzinfo — \
             which compares incorrectly against any aware datetime and is \
             scheduled for removal. Use `datetime.now(tz=UTC)` instead."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `datetime.utcnow()` with `datetime.now(tz=timezone.utc)`.".into(),
        ),
        snippet: text,
        weight: 2,
    }))
}
