//! `cc.compliance.pii_handling` — PII-named field without an
//! encryption-at-rest hint.
//!
//! Heuristic: enumerate every [`NodeKind::Variable`] node whose `name`
//! property matches a [`PII_KEYWORD_TABLE`](crate::helpers::PII_KEYWORD_TABLE)
//! entry. For each hit, look at:
//!
//! - the variable's own `type` / `target_type` / `annotation` props,
//! - any sibling `Decorator` AST children of the same parent,
//!
//! and silence the probe whenever any of those surfaces carry an
//! [`ENCRYPTION_HINTS`](crate::helpers::ENCRYPTION_HINTS) marker
//! (`encrypted`, `kms`, `vault`, …).
//!
//! Test-file paths and rule-pack-source paths are skipped — the
//! pii_handling probe should not flag fixtures or its own keyword
//! table.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, looks_encrypted,
    looks_like_pii_name, looks_like_rule_pack_source, ComplianceFindingBlueprint,
};

/// Family-21 probe R-PII-HANDLING.
#[derive(Debug, Default, Clone, Copy)]
pub struct PiiHandlingRule;

impl Rule for PiiHandlingRule {
    fn rule_id(&self) -> &'static str {
        "cc.compliance.pii_handling"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Compliance
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "field whose name suggests PII has no encryption-at-rest hint"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
            if let Some(finding) = check_variable(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_variable(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let name = string_prop(ctx.batch, node.id, "name")?;
    if !looks_like_pii_name(name) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if has_encryption_hint(ctx, node.id) {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ComplianceFindingBlueprint {
        rule_id: "cc.compliance.pii_handling",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("PII field `{name}` has no encryption-at-rest hint"),
        explanation: format!(
            "`{name}` matches the PII keyword table (email / ssn / phone / dob / \
             address / passport / credit_card / tax_id / national_id). Storing \
             this without an encryption-at-rest marker (`encrypted`, `kms`, \
             `vault`, `cipher`, etc.) risks GDPR / CCPA / HIPAA violation."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the field in an `Encrypted<…>` / `EncryptedField` / KMS-backed \
             type, or apply a decorator / annotation that names the encryption \
             scheme. If this field is a non-sensitive false positive (e.g. a \
             public mailto), rename it so the PII keyword no longer matches."
                .into(),
        ),
        snippet: format!("{name}: …"),
        weight: 3,
    }))
}

fn has_encryption_hint(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if self_carries_hint(ctx, id) {
        return true;
    }
    sibling_decorator_hint(ctx, id)
}

fn self_carries_hint(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    for key in &["type", "target_type", "annotation", "initializer"] {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if looks_encrypted(value) {
                return true;
            }
        }
    }
    false
}

fn sibling_decorator_hint(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, id) else {
        return false;
    };
    for child in ast_children(ctx.batch, parent) {
        if !matches!(node_kind(ctx.batch, child), Some(NodeKind::Decorator)) {
            continue;
        }
        if decorator_has_hint(ctx, child) {
            return true;
        }
    }
    false
}

fn decorator_has_hint(ctx: &RuleContext<'_>, decorator: NodeId) -> bool {
    for key in &["name", "qualified", "expression"] {
        if let Some(value) = string_prop(ctx.batch, decorator, key) {
            if looks_encrypted(value) {
                return true;
            }
        }
    }
    false
}
