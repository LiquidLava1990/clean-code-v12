//! `cc.obs.unstructured_log` — log call whose only argument is a literal
//! string (no structured fields, no key=value pairs).
//!
//! Heuristic (Phase-4 simplification): for every [`NodeKind::Call`] whose
//! callee text matches an info / warn / error log primitive, look at the
//! `args` property. If `args` is a single string literal with no
//! structured-log markers (`%(...)s`, `=` inside `{...}`, comma-separated
//! key/value pairs, or a `fields` / `kwargs` slot), fire.
//!
//! Severity: Nit. The probe is intentionally noisy-neutral — it's a
//! style nudge.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_matches, callee_text, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, ObsFindingBlueprint, LOG_CALLEES,
};

/// Family-11 probe R-OBS-UNSTRUCTURED-LOG.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnstructuredLogRule;

const LOG_LEVEL_NEEDLES: &[&str] = &[
    ".info(",
    ".warn(",
    ".warning(",
    ".error(",
    "::info!",
    "::warn!",
    "::error!",
    ".Info(",
    ".Warn(",
    ".Error(",
    "console.log",
    "console.info",
    "console.warn",
    "console.error",
];

impl Rule for UnstructuredLogRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.unstructured_log"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "log call uses a single literal string with no structured fields"
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
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let text = callee_text(ctx.batch, id);
    if !is_log_call(&text) {
        return None;
    }
    let args = string_prop(ctx.batch, id, "args").unwrap_or("");
    if has_structured_markers(args) {
        return None;
    }
    if !args_are_single_literal(args) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(emit(location, args))
}

fn is_log_call(text: &str) -> bool {
    callee_matches(text, LOG_CALLEES) || LOG_LEVEL_NEEDLES.iter().any(|n| text.contains(n))
}

fn has_structured_markers(args: &str) -> bool {
    args.contains('=')
        || args.contains("%(")
        || args.contains("fields=")
        || args.contains("kwargs=")
        || args.contains("**")
        || args.contains(", ")
}

fn args_are_single_literal(args: &str) -> bool {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return false;
    }
    let starts = trimmed.starts_with('"') || trimmed.starts_with('\'') || trimmed.starts_with('`');
    let ends = trimmed.ends_with('"') || trimmed.ends_with('\'') || trimmed.ends_with('`');
    starts && ends
}

fn emit(location: cc_finding::Location, args: &str) -> Finding {
    let snippet: String = args.chars().take(120).collect();
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.unstructured_log",
        severity: Severity::Nit,
        confidence: Confidence::new(0.6),
        location,
        headline: "log call has no structured fields".into(),
        explanation: "The log call passes a single literal string with no \
             key/value fields. Downstream log processors cannot index, \
             filter, or aggregate on the message — every search becomes a \
             grep. Structured logging carries the same human text plus \
             machine-readable fields."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass key/value fields alongside the message. Examples: \
             `tracing::info!(user_id = %uid, \"created\")`, \
             `logger.info(\"created\", extra={\"user_id\": uid})`, \
             `slog.Info(\"created\", \"user_id\", uid)`."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
