//! `cc.config.secret_in_code` — flag string literals that look like
//! checked-in credentials.
//!
//! Detection has two paths:
//!
//! 1. **Known-vendor patterns** — AWS / GitHub / Slack / Stripe / JWT /
//!    private-key headers. Cheap byte-level prefix + charset checks
//!    via `crate::helpers::match_known_secret`. Always fires
//!    regardless of surrounding identifier.
//! 2. **Generic high-entropy** — Shannon entropy ≥
//!    `MIN_ENTROPY_BITS` and
//!    length ≥ `MIN_GENERIC_LEN`,
//!    *and* the literal is the RHS of an assignment to a credential-
//!    bearing variable name (`*_key` / `*_secret` / `*_token` / …).
//!
//! Findings are skipped whenever the enclosing file is a test fixture
//! (heuristic — see `crate::helpers::is_test_file_path`); test
//! fixtures legitimately contain canonical example tokens.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, entropy_score, is_test_file_path, location_from_node,
    looks_like_credential_name, match_known_secret, SecretKind, SecretsFindingBlueprint,
    MIN_ENTROPY_BITS, MIN_GENERIC_LEN,
};

/// Family-19 probe R-SECRET-IN-CODE.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecretInCodeRule;

impl Rule for SecretInCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.secret_in_code"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "string literal looks like a checked-in secret / credential"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Literal) {
            if let Some(finding) = check_literal(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_literal(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let value = string_prop(ctx.batch, id, "value")?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let kind = classify(ctx, id, value)?;
    let location = location_from_node(ctx.batch, id, path);
    let label = kind.label();
    Some(build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.secret_in_code",
        category: Category::Config,
        severity: Severity::Blocker,
        confidence: Confidence::new(confidence_for(kind)),
        location,
        headline: format!("possible {label} checked into source"),
        explanation: format!(
            "A string literal matching the {label} shape was found in source. \
             Real credentials must never live in the repo — even short-lived \
             tokens are a leak."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Move the value to a secret manager (env var, Vault, AWS Secrets \
             Manager, Doppler) and reference it through the runtime config layer. \
             If this is an example/test value, move it under a `tests/` path so \
             this rule's test-file heuristic skips it."
                .into(),
        ),
        snippet: snippet_for(value),
        weight: 5,
    }))
}

fn classify(ctx: &RuleContext<'_>, id: NodeId, value: &str) -> Option<SecretKind> {
    if let Some(kind) = match_known_secret(value) {
        return Some(kind);
    }
    if value.len() >= MIN_GENERIC_LEN
        && entropy_score(value) >= MIN_ENTROPY_BITS
        && enclosing_credential_name(ctx, id).is_some()
    {
        return Some(SecretKind::Generic);
    }
    None
}

/// Walk up the AST for an enclosing `Write`/`Variable` node whose
/// target (or `name` prop) looks like a credential identifier.
fn enclosing_credential_name(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    let parent = ast_parent(ctx.batch, id)?;
    let parent_kind = node_kind(ctx.batch, parent)?;
    let candidate = match parent_kind {
        NodeKind::Write => string_prop(ctx.batch, parent, "target"),
        NodeKind::Variable => string_prop(ctx.batch, parent, "name"),
        _ => None,
    }?;
    if looks_like_credential_name(candidate) {
        Some(candidate.to_owned())
    } else {
        sibling_credential_name(ctx, parent)
    }
}

fn sibling_credential_name(ctx: &RuleContext<'_>, write_id: NodeId) -> Option<String> {
    for child in ast_children(ctx.batch, write_id) {
        if let Some(name) = identifier_credential_name(ctx, child) {
            return Some(name);
        }
    }
    None
}

/// Read `child` as an `Identifier` whose `name` looks like a credential
/// identifier — returns the owned name on a hit, `None` otherwise.
fn identifier_credential_name(ctx: &RuleContext<'_>, child: NodeId) -> Option<String> {
    if !matches!(node_kind(ctx.batch, child), Some(NodeKind::Identifier)) {
        return None;
    }
    let name = string_prop(ctx.batch, child, "name")?;
    if !looks_like_credential_name(name) {
        return None;
    }
    Some(name.to_owned())
}

const fn confidence_for(kind: SecretKind) -> f32 {
    match kind {
        SecretKind::Generic => 0.7,
        _ => 0.95,
    }
}

fn snippet_for(value: &str) -> String {
    let preview_len = value.len().min(8);
    format!("{}…[redacted, len={}]", &value[..preview_len], value.len())
}
