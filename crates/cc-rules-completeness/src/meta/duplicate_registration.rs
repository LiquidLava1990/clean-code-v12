//! `cc.meta.duplicate_registration` — two distinct functions claim the
//! same registry key (decorator argument string `name = "..."`).

use std::collections::BTreeMap;

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, decorator_arg_name, enclosing_file_path, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.meta.duplicate_registration`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DuplicateRegistrationRule;

impl Rule for DuplicateRegistrationRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.duplicate_registration"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "two functions register under the same name"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let claims = collect_claims(ctx);
        emit_collisions(ctx, &claims)
    }
}

fn collect_claims(ctx: &RuleContext<'_>) -> BTreeMap<String, Vec<NodeId>> {
    let mut claims: BTreeMap<String, Vec<NodeId>> = BTreeMap::new();
    for dec in nodes_of_kind(ctx.batch, NodeKind::Decorator) {
        let dec_name = string_prop(ctx.batch, dec.id, "name").unwrap_or("");
        if !is_registry_decorator(dec_name) {
            continue;
        }
        if let Some(arg) = decorator_arg_name(ctx.batch, dec.id) {
            claims.entry(arg.to_owned()).or_default().push(dec.id);
        }
    }
    claims
}

fn emit_collisions(ctx: &RuleContext<'_>, claims: &BTreeMap<String, Vec<NodeId>>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (key, ids) in claims {
        if ids.len() < 2 {
            continue;
        }
        for id in ids {
            if let Some(f) = build_collision_finding(ctx, *id, key, ids.len()) {
                out.push(f);
            }
        }
    }
    out
}

fn build_collision_finding(
    ctx: &RuleContext<'_>,
    id: NodeId,
    key: &str,
    count: usize,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.meta.duplicate_registration",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("registry key `{key}` claimed by {count} sites"),
        explanation: "Two registrations under the same name silently overwrite one \
             another at boot. The loser disappears from the meta-registry but the \
             code still runs — failures look like missing functions in production."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Pick distinct names (one per concept, per S5 doctrine) — rename one of the \
             `{key}` registrations."
        )),
        snippet: key.to_owned(),
        weight: 2,
    }))
}

fn is_registry_decorator(name: &str) -> bool {
    name.contains("register")
        || name.contains("instrument")
        || name.contains("trace_async")
        || name.contains("meta_async")
}
