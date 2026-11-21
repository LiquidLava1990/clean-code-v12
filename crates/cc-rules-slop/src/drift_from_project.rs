//! `cc.slop.drift_from_project` — flag identifiers whose naming style
//! drifts from the dominant style for that NodeKind in the same lifted
//! batch.
//!
//! Phase-2 implementation: build a per-batch [`cc_fingerprint::Fingerprint`]
//! by rolling the current `CpgWriteBatch` through a one-shot
//! [`cc_fingerprint::FingerprintBuilder`], then call
//! [`cc_fingerprint::Fingerprint::is_naming_outlier`] for each identifier.
//!
//! The doctrine target is repo-wide drift; once `RuleContext::project`
//! carries a real fingerprint we will switch to it without a behavioural
//! change. Until then a per-batch fingerprint correctly flags
//! intra-file drift, which is the most actionable subset.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_fingerprint::{Fingerprint, FingerprintBuilder};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, enclosing_language, location_from_node,
    SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-DRIFT.
#[derive(Debug, Default, Clone, Copy)]
pub struct DriftFromProjectRule;

impl Rule for DriftFromProjectRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.drift_from_project"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "identifier naming style drifts from the rest of the project"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(fingerprint) = build_batch_fingerprint(ctx.batch) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for kind in [
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Class,
            NodeKind::Variable,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_outlier(ctx, &fingerprint, node.id, kind) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

/// Build a Fingerprint from this single batch. Returns `None` when the
/// batch lacks the language property (the builder cannot work without
/// one).
fn build_batch_fingerprint(batch: &CpgWriteBatch) -> Option<Fingerprint> {
    let language = batch_language(batch)?;
    let mut builder = FingerprintBuilder::new();
    builder.add_file(batch, &language).ok()?;
    Some(builder.finalize())
}

fn batch_language(batch: &CpgWriteBatch) -> Option<String> {
    for node in batch.nodes() {
        if node.kind == NodeKind::File {
            if let Some(cc_cpg::Value::String(lang)) = node.prop("language") {
                return Some(lang.clone());
            }
        }
    }
    None
}

fn check_outlier(
    ctx: &RuleContext<'_>,
    fingerprint: &Fingerprint,
    id: NodeId,
    kind: NodeKind,
) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if name.starts_with('_') || name.len() < 3 {
        return None;
    }
    if !fingerprint.is_naming_outlier(kind, name) {
        return None;
    }
    let language = enclosing_language(ctx.batch, id).unwrap_or_else(|| "unknown".to_owned());
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.drift_from_project",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("identifier `{name}` drifts from the project's dominant style"),
        explanation: format!(
            "Identifier `{name}` ({language}, {kind:?}) does not match the \
             dominant naming style for this kind in the surrounding code. \
             Mixed styles confuse readers and break grep-driven workflows."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename `{name}` to match the project's existing convention for \
             this kind of identifier."
        )),
        snippet: String::new(),
        weight: 1,
    }))
}
