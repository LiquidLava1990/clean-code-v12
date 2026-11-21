//! `cc.convention.untyped_event` — events use typed contracts.
//!
//! Events emitted via the EventBus must come from a typed contract —
//! never an inline string literal. The probe walks every
//! [`NodeKind::Call`] inside a `platform/` tree and flags calls to the
//! recognised emit functions whose first argument is a string literal.
//!
//! Phase-3 simplification: contract resolution (matching the literal
//! against declared `event_name: str` class fields) is deferred to
//! Phase 4 once the persistent CPG store lands. Until then any literal
//! event name is treated as a violation — false positives are
//! preferred over silent typing drift.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, first_arg_literal, is_layout_path,
    location_from_node, ConventionFindingBlueprint,
};

/// Family-24 probe R-CONVENTION-UNTYPED-EVENT.
#[derive(Debug, Default, Clone, Copy)]
pub struct UntypedEventRule;

/// Recognised EventBus emit callees across Python / Rust frontends.
const EMIT_CALLEES: &[&str] = &[
    "bus.emit",
    "bus.publish",
    "event_bus.emit",
    "event_bus.publish",
    "EventBus.emit",
    "EventBus.publish",
    "EventBus::emit",
    "EventBus::publish",
    "self.bus.emit",
    "self.bus.publish",
    "self.event_bus.emit",
    "self.event_bus.publish",
];

impl Rule for UntypedEventRule {
    fn rule_id(&self) -> &'static str {
        "cc.convention.untyped_event"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Convention
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "EventBus emit uses a string-literal event name — declare a typed contract instead"
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

fn check_call(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    if !is_layout_path(&path) {
        return None;
    }
    let callee = callee_text(ctx.batch, call);
    if !EMIT_CALLEES.iter().any(|n| callee.contains(n)) {
        return None;
    }
    let event = first_arg_literal(ctx.batch, call)?;
    Some(emit(ctx, call, path, &event))
}

fn emit(ctx: &RuleContext<'_>, call: NodeId, path: camino::Utf8PathBuf, event: &str) -> Finding {
    let location = location_from_node(ctx.batch, call, path);
    build_finding(ConventionFindingBlueprint {
        rule_id: "cc.convention.untyped_event",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("EventBus emit uses string literal `\"{event}\"`"),
        explanation: format!(
            "Layout convention: every event name flowing through the \
             EventBus is a typed contract — declared on a contract \
             class as `event_name: str = \"...\"`, so the registry can \
             validate the payload + route to subscribers. The literal \
             `\"{event}\"` bypasses that contract; if the receiver \
             renames the event, this caller silently stops firing."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the literal with a reference to the typed event \
             contract: `bus.emit(MyEvent.event_name, payload)`. If the \
             contract does not exist yet, add it under \
             `platform/foundation/events/<domain>.py` and re-emit."
                .into(),
        ),
        snippet: format!("emit(\"{event}\", …)"),
        weight: 3,
    })
}
