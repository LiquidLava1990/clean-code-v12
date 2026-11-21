//! `cc.obs.pii_in_log` — PII keyword found inside a log format string.
//!
//! Heuristic (Phase-4 simplification): every [`NodeKind::Call`] whose
//! callee text matches a log primitive ([`crate::helpers::LOG_CALLEES`])
//! has its `format` / `args` property scanned for any of the
//! [`crate::helpers::PII_KEYWORDS`] substrings (presidio + scrubadub
//! keyword set).
//!
//! Severity: Blocker. PII landing in logs is a privacy / compliance
//! incident.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_matches, callee_text, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, ObsFindingBlueprint, LOG_CALLEES,
    PII_KEYWORDS,
};

/// Family-11 probe R-OBS-PII-IN-LOG.
#[derive(Debug, Default, Clone, Copy)]
pub struct PiiInLogRule;

impl Rule for PiiInLogRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.pii_in_log"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "log format string contains a PII keyword (email / ssn / phone / ...)"
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
    if !callee_matches(&text, LOG_CALLEES) {
        return None;
    }
    let fmt = log_format_text(ctx, id);
    let offender = matched_pii(&fmt)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(emit(location, offender, &fmt))
}

fn log_format_text(ctx: &RuleContext<'_>, id: NodeId) -> String {
    let mut buf = String::new();
    for key in ["format", "args", "message"] {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    buf
}

fn matched_pii(fmt: &str) -> Option<&'static str> {
    let lower = fmt.to_ascii_lowercase();
    PII_KEYWORDS.iter().find(|k| lower.contains(*k)).copied()
}

fn emit(location: cc_finding::Location, offender: &str, fmt: &str) -> Finding {
    let snippet: String = fmt.chars().take(160).collect();
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.pii_in_log",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("log format string mentions `{offender}` — likely PII leak"),
        explanation: format!(
            "The log format string contains `{offender}`, which matches a \
             presidio / scrubadub PII keyword. PII (email, SSN, phone, \
             address, credit card, full name, DOB, password, API key, \
             token) in logs is a compliance violation — log streams ship \
             to indexers, third-party SaaS, and long-term cold storage \
             that the PII consent envelope does not cover."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Hash, redact, or drop the PII field before logging. Log a \
             stable opaque id (`user_id` / `account_id`) instead of the \
             raw value, and scrub the format string."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
