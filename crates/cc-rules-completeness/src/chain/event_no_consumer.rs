//! `cc.chain.event_no_consumer` — event-emit call where the event-name
//! string isn't matched by any subscriber in the batch.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::chain::collect_event_names;
use crate::helpers::{
    build_finding, enclosing_file_path, is_emit_callee, is_subscribe_callee, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.chain.event_no_consumer`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventNoConsumerRule;

impl Rule for EventNoConsumerRule {
    fn rule_id(&self) -> &'static str {
        "cc.chain.event_no_consumer"
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
        "event emitted with no subscriber in the batch"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let consumers = collect_event_names(ctx, is_subscribe_callee);
        let mut out = Vec::new();
        for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
            let callee = string_prop(ctx.batch, call.id, "name").unwrap_or("");
            if !is_emit_callee(callee) {
                continue;
            }
            let Some(event) = string_prop(ctx.batch, call.id, "event_name") else {
                continue;
            };
            if consumers.contains(event) {
                continue;
            }
            if let Some(f) = build_orphan_emit(ctx, call.id, event) {
                out.push(f);
            }
        }
        out
    }
}

fn build_orphan_emit(ctx: &RuleContext<'_>, id: NodeId, event: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.chain.event_no_consumer",
        category: Category::Arch,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("event `{event}` is emitted but has no consumer"),
        explanation: "Emitting an event nobody subscribes to is dead work — the producer \
             pays the serialisation cost while no consumer reacts. Either delete the \
             emit or add a subscriber."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add a subscriber for `{event}` or remove the emit."
        )),
        snippet: event.to_owned(),
        weight: 1,
    }))
}
