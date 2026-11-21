//! `cc.meta.envelope_missing` — public function returning a generic
//! `Result<T, E>` / `Box<dyn Error>` / `anyhow::Error` rather than a
//! specific envelope type.
//!
//! Phase-2 heuristic: read the function's `return_type` string property
//! emitted by the lift pass. If it matches one of the well-known
//! generic-error patterns, the function lacks a dedicated error
//! envelope and is flagged.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_public_fn, is_top_level_fn, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.meta.envelope_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvelopeMissingRule;

const GENERIC_ERROR_NEEDLES: &[&str] = &[
    "Box<dyn Error",
    "Box<dyn std::error::Error",
    "anyhow::Error",
    "anyhow::Result",
    "Result<_, Error>",
    "Result<(), Error>",
];

impl Rule for EnvelopeMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.envelope_missing"
    }
    fn category(&self) -> Category {
        Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "public fn returns a generic error type — no envelope"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Function) {
            if let Some(f) = check_fn(ctx, node.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    if !is_public_fn(ctx.batch, id) {
        return None;
    }
    let return_type = string_prop(ctx.batch, id, "return_type")?;
    if !GENERIC_ERROR_NEEDLES
        .iter()
        .any(|n| return_type.contains(n))
    {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.meta.envelope_missing",
        category: Category::Api,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name}` returns a generic error — no envelope"),
        explanation: "Public APIs returning `Box<dyn Error>` / `anyhow::Error` make \
             callers guess what failures are recoverable. Define a domain-specific \
             error enum with stable variants."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the generic error with a `thiserror`/`pydantic` envelope that \
             names each failure mode + carries a stable `ErrCode`."
                .into(),
        ),
        snippet: return_type.to_owned(),
        weight: 1,
    }))
}
