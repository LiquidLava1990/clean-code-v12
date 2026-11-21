//! `cc.chain.consumer_no_emitter` — subscriber `on_event("X")` where
//! `X` isn't emitted anywhere in the batch.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::chain::collect_event_names;
use crate::helpers::{
    build_finding, enclosing_file_path, is_emit_callee, is_subscribe_callee, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.chain.consumer_no_emitter`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsumerNoEmitterRule;

impl Rule for ConsumerNoEmitterRule {
    fn rule_id(&self) -> &'static str {
        "cc.chain.consumer_no_emitter"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "consumer subscribes to an event with no emitter in the batch"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let emitters = collect_event_names(ctx, is_emit_callee);
        let mut out = Vec::new();
        for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
            let callee = string_prop(ctx.batch, call.id, "name").unwrap_or("");
            if !is_subscribe_callee(callee) {
                continue;
            }
            let Some(event) = string_prop(ctx.batch, call.id, "event_name") else {
                continue;
            };
            if emitters.contains(event) {
                continue;
            }
            if let Some(f) = build_orphan_consumer(ctx, call.id, event) {
                out.push(f);
            }
        }
        out
    }
}

fn build_orphan_consumer(ctx: &RuleContext<'_>, id: NodeId, event: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.chain.consumer_no_emitter",
        category: Category::Arch,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("consumer subscribed to `{event}` — no emitter found"),
        explanation: "A subscriber waiting on an event that nothing emits sits in dead \
             code. Either remove the subscriber or add the emitter."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add an emitter for `{event}` or delete the subscription."
        )),
        snippet: event.to_owned(),
        weight: 1,
    }))
}
