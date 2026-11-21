//! `cc.obs.high_cardinality_label` — metric label is a user / request /
//! session id, email, path, or URL.
//!
//! Heuristic: every [`NodeKind::Call`] whose callee text matches a
//! metric primitive (`crate::helpers::METRIC_CALLEES`) has its `args`
//! property scanned for any of `crate::helpers::HIGH_CARDINALITY_LABELS`.
//! A match fires the rule.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_matches, callee_text, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, ObsFindingBlueprint, HIGH_CARDINALITY_LABELS,
    METRIC_CALLEES,
};

/// Family-11 probe R-OBS-HIGH-CARDINALITY-LABEL.
#[derive(Debug, Default, Clone, Copy)]
pub struct HighCardinalityLabelRule;

impl Rule for HighCardinalityLabelRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.high_cardinality_label"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "metric label set includes a high-cardinality identifier"
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
    if !callee_matches(&text, METRIC_CALLEES) {
        return None;
    }
    let args = string_prop(ctx.batch, id, "args").unwrap_or("");
    let offender = matched_label(args)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(emit(location, offender, args))
}

fn matched_label(args: &str) -> Option<&'static str> {
    let lower = args.to_ascii_lowercase();
    HIGH_CARDINALITY_LABELS
        .iter()
        .find(|l| lower.contains(*l))
        .copied()
}

fn emit(location: cc_finding::Location, offender: &str, args: &str) -> Finding {
    let snippet: String = args.chars().take(160).collect();
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.high_cardinality_label",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("metric label `{offender}` will explode time-series cardinality"),
        explanation: format!(
            "Using `{offender}` as a metric label creates one time-series \
             per distinct value — Prometheus / StatsD / Datadog charge by \
             cardinality, and the metric becomes unqueryable past a few \
             thousand values. High-cardinality identifiers belong on \
             *exemplars* or *traces*, never on metric labels."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Drop the high-cardinality label. If per-id breakdown is \
             needed for debugging, attach the id as a tracing attribute \
             on the surrounding span or as an exemplar on the histogram."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
