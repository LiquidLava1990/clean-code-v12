//! `cc.db.json_blob_hellscape` — JSON column where relational would fit.
//!
//! Heuristic: walk every [`NodeKind::Variable`] (frontend lifts class
//! fields as Variable nodes carrying `name` + `type` props). Flag fields
//! whose declared type is one of:
//!
//! - SQLAlchemy: `Column(JSON)`, `Column(JSONB)`
//! - Django: `models.JSONField`
//! - Diesel / serde: `serde_json::Value`
//!
//! AND whose name starts with a structured prefix (`config_`,
//! `settings_`, `data_`, `metadata_`) AND ends with `_dict` or `_blob`.
//! The combined signal is conservative — bare `data` columns or
//! Postgres-native `jsonb` for free-form telemetry are not flagged.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    DatabaseFindingBlueprint, JSON_BLOB_FIELD_PATTERNS, JSON_BLOB_SUFFIXES,
};

/// Family-10 probe R-DB-JSON-BLOB-HELLSCAPE.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonBlobHellscapeRule;

const JSON_TYPE_NEEDLES: &[&str] = &[
    "Column(JSON)",
    "Column(JSONB)",
    "Column(JSON,",
    "Column(JSONB,",
    "models.JSONField",
    "JSONField(",
    "serde_json::Value",
];

impl Rule for JsonBlobHellscapeRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.json_blob_hellscape"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "JSON column carries structured data that belongs in relational tables"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
            if let Some(finding) = check_field(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_field(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    let ty = string_prop(ctx.batch, id, "type")?;
    if !is_json_typed(ty) {
        return None;
    }
    if !looks_structured(name) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(DatabaseFindingBlueprint {
        rule_id: "cc.db.json_blob_hellscape",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("JSON column `{name}` carries structured data"),
        explanation: format!(
            "`{name}` is declared as a JSON / JSONB column but the field name \
             (`{name}`) suggests structured rows: keys, types, and access \
             paths are knowable up-front. JSON columns lose query plans, \
             foreign keys, partial indexes, and CHECK constraints; they push \
             validation into application code where it rots. Promote the \
             keys to real columns or a dedicated child table."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the JSON column with a relational schema: either add \
             columns to the same table for a small, fixed key set, or create \
             a child table keyed by the parent id for variable-cardinality \
             data. Keep JSON columns only for genuinely opaque blobs (audit \
             payloads, third-party webhooks)."
                .into(),
        ),
        snippet: format!("{name}: {ty}"),
        weight: 3,
    }))
}

fn is_json_typed(ty: &str) -> bool {
    JSON_TYPE_NEEDLES.iter().any(|n| ty.contains(n))
}

fn looks_structured(name: &str) -> bool {
    let prefix_match = JSON_BLOB_FIELD_PATTERNS.iter().any(|p| name.starts_with(p));
    let suffix_match = JSON_BLOB_SUFFIXES.iter().any(|s| name.ends_with(s));
    prefix_match && suffix_match
}
