//! `cc.convention.file_claim_bypass` — claimed writes to `data/`.
//!
//! Writes under `data/` MUST flow through
//! `FileClaimRegistry::sync_claim_scope`. The probe mirrors the
//! `cc_rules_concurrency::file_claim_bypass` pattern but is gated on
//! `platform/` paths and escalated to Blocker inside the layout.
//!
//! Heuristic: scan every function body for write-style Calls
//! (`open(p, "w")` / `fs.writeFileSync(p)` / `std::fs::write` /
//! `File::create` / `Path::write` / `os.Create` / `ioutil.WriteFile`)
//! whose path argument lives under `data/`. If the function body
//! contains no preceding `FileClaimRegistry::sync_claim_scope` call,
//! flag the write.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, collect_descendant_calls, enclosing_file_path, first_arg_text,
    is_layout_path, is_protected_data_path, location_from_node, ConventionFindingBlueprint,
};

/// Family-24 probe R-CONVENTION-FILE-CLAIM-BYPASS.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileClaimBypassRule;

/// Callee texts treated as protected-directory writes.
const WRITE_CALLEES: &[&str] = &[
    "open",
    "io.open",
    "fs.writeFileSync",
    "fs.writeFile",
    "std::fs::write",
    "File::create",
    "os.Create",
    "ioutil.WriteFile",
    "Path::write",
];

const CLAIM_CALLEES: &[&str] = &[
    "FileClaimRegistry::sync_claim_scope",
    "sync_claim_scope",
    "FileClaimRegistry.sync_claim_scope",
    "claim_scope",
];

impl Rule for FileClaimBypassRule {
    fn rule_id(&self) -> &'static str {
        "cc.convention.file_claim_bypass"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Convention
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "`platform/` write to `data/` bypasses FileClaimRegistry::sync_claim_scope"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for fun in nodes_of_kind(ctx.batch, kind) {
                scan_function(ctx, fun.id, &mut out);
            }
        }
        out
    }
}

fn scan_function(ctx: &RuleContext<'_>, fun: NodeId, out: &mut Vec<Finding>) {
    let mut calls: Vec<NodeId> = Vec::new();
    collect_descendant_calls(ctx.batch, fun, &mut calls);
    if calls.is_empty() {
        return;
    }
    let claim_pos = find_claim_position(ctx, &calls);
    for (idx, call) in calls.iter().enumerate() {
        if !is_protected_write(ctx, *call) {
            continue;
        }
        if claim_pos.is_some_and(|p| p < idx) {
            continue;
        }
        if let Some(finding) = emit(ctx, *call) {
            out.push(finding);
        }
    }
}

fn find_claim_position(ctx: &RuleContext<'_>, calls: &[NodeId]) -> Option<usize> {
    calls.iter().position(|c| {
        CLAIM_CALLEES
            .iter()
            .any(|n| callee_text(ctx.batch, *c).contains(n))
    })
}

fn is_protected_write(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    let text = callee_text(ctx.batch, call);
    if !WRITE_CALLEES.iter().any(|n| text.contains(n)) {
        return false;
    }
    let Some(arg) = first_arg_text(ctx.batch, call) else {
        return false;
    };
    is_protected_data_path(&arg)
}

fn emit(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    if !is_layout_path(&path) {
        return None;
    }
    let arg = first_arg_text(ctx.batch, call).unwrap_or_default();
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(ConventionFindingBlueprint {
        rule_id: "cc.convention.file_claim_bypass",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("write to `{arg}` bypasses FileClaimRegistry::sync_claim_scope"),
        explanation: format!(
            "Layout convention: writes under `data/` MUST acquire a \
             claim via `FileClaimRegistry::sync_claim_scope` first. \
             Writing to `{arg}` without one lets two workers race the \
             same path and silently corrupt the shared tree."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the write in `with FileClaimRegistry.sync_claim_scope(\"<scope>\"):` \
             (or the Rust / Go equivalent). If this is a single-threaded \
             bootstrap path, document the exception with a \
             `# noqa: convention-file-claim-bypass` comment."
                .into(),
        ),
        snippet: arg,
        weight: 5,
    }))
}
