//! `cc.meta.io_schema_missing` — function whose name implies (de)serialisation
//! but carries no documented schema reference.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, is_top_level_fn,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.meta.io_schema_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct IoSchemaMissingRule;

const SCHEMA_NEEDLES: &[&str] = &[
    "JSONSchema",
    "json_schema",
    "BaseModel",
    "TypedDict",
    "Pydantic",
    "pydantic",
    "schema",
    "Schema",
    "#[serde",
    "@dataclass",
];

impl Rule for IoSchemaMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.meta.io_schema_missing"
    }
    fn category(&self) -> Category {
        Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "(de)serialisation fn lacks a documented schema reference"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_fn(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_serde_name(name) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source).unwrap_or_default();
    if body_contains_any(&body, SCHEMA_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.meta.io_schema_missing",
        category: Category::Api,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{name}` parses/produces data without a schema reference"),
        explanation: "Functions that bridge external data to internal types must \
             reference a schema (Pydantic class, JSON-schema, serde struct). Otherwise \
             the contract is implicit and decays."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Reference a schema via `BaseModel` / `#[derive(Deserialize)]` / a \
             documented JSON-schema URL in the docstring."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

fn is_serde_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("serialize_")
        || lower.starts_with("deserialize_")
        || lower == "to_json"
        || lower == "from_json"
        || lower.starts_with("parse_")
        || lower.starts_with("encode_")
        || lower.starts_with("decode_")
}
