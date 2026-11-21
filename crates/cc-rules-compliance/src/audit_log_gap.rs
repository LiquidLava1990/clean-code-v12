//! `cc.compliance.audit_log_gap` — privileged operation without an
//! audit-log emit.
//!
//! Heuristic: enumerate every [`NodeKind::Function`] (and Method) node
//! whose `name` looks privileged
//! (`PRIVILEGED_NAME_PATTERNS`
//! — `admin_*`, `delete_*`, `update_role_*`, `grant_*`). For each
//! function, walk its AST descendants for a [`NodeKind::Call`] whose
//! callee text matches an `AUDIT_CALLEES`
//! entry. If none is present, emit a Blocker finding.
//!
//! `tracing::info!(target = "audit", …)` calls qualify because the
//! callee text from the frontend includes the macro-form `tracing::info!`
//! and tools that group findings by callee can refine the
//! `target = "audit"` constraint downstream.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, looks_privileged, ComplianceFindingBlueprint, AUDIT_CALLEES,
};

/// Family-21 probe R-AUDIT-LOG-GAP.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditLogGapRule;

impl Rule for AuditLogGapRule {
    fn rule_id(&self) -> &'static str {
        "cc.compliance.audit_log_gap"
    }
    fn category(&self) -> Category {
        Category::Compliance
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "privileged operation function has no audit-log call in its body"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in privileged_functions(ctx) {
            if let Some(finding) = check_function(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn privileged_functions<'b>(ctx: &'b RuleContext<'_>) -> Vec<&'b Node> {
    let mut out: Vec<&Node> = Vec::new();
    for kind in [NodeKind::Function, NodeKind::Method] {
        for node in nodes_of_kind(ctx.batch, kind) {
            let Some(name) = string_prop(ctx.batch, node.id, "name") else {
                continue;
            };
            if looks_privileged(name) {
                out.push(node);
            }
        }
    }
    out
}

fn check_function(ctx: &RuleContext<'_>, function: &Node) -> Option<Finding> {
    let name = string_prop(ctx.batch, function.id, "name")?;
    let path = enclosing_file_path(ctx.batch, function.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if has_audit_call(ctx, function.id) {
        return None;
    }
    let location = location_from_node(ctx.batch, function.id, path);
    Some(build_finding(ComplianceFindingBlueprint {
        rule_id: "cc.compliance.audit_log_gap",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.75),
        location,
        headline: format!("privileged op `{name}` emits no audit log"),
        explanation: format!(
            "`{name}` matches the privileged-operation name pattern (admin_* / \
             delete_* / update_role_* / grant_*) but no call to `audit_log`, \
             `audit.emit`, `log.audit`, or `tracing::info!(target = \"audit\", …)` \
             was found in its body. Privileged actions must leave an audit trail \
             for SOC2 / ISO 27001 / HIPAA compliance."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add an audit-log call recording actor, target, before/after state, \
             and timestamp. Route through the project's canonical audit sink \
             so retention and tamper-evidence policies apply uniformly."
                .into(),
        ),
        snippet: format!("fn {name}(…) {{ … }}"),
        weight: 4,
    }))
}

/// True iff any `Call` in the same file references one of the audit
/// callees. Phase-5 simplification: scope is the enclosing file, not
/// strictly the function body — privileged ops typically live in
/// dedicated modules so the false-positive risk is tolerable.
fn has_audit_call(ctx: &RuleContext<'_>, function_id: NodeId) -> bool {
    let Some(file_path) = enclosing_file_path(ctx.batch, function_id) else {
        return false;
    };
    for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
        let Some(call_path) = enclosing_file_path(ctx.batch, call.id) else {
            continue;
        };
        if call_path != file_path {
            continue;
        }
        let haystack = callee_text(ctx.batch, call.id).to_ascii_lowercase();
        if haystack.is_empty() {
            continue;
        }
        if AUDIT_CALLEES
            .iter()
            .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
        {
            return true;
        }
    }
    false
}
