//! `cc.concurrent.file_claim_bypass` — writes to a shared `data/...` tree
//! without a preceding `FileClaimRegistry::sync_claim_scope` call in the
//! same function.
//!
//! Heuristic: scan every function body for write-style Calls
//! (`open(p, "w")` / `fs.writeFileSync(p)` / `std::fs::write` /
//! `File::create`) whose path argument starts with `data/`. If the
//! function body contains no preceding `FileClaimRegistry::sync_claim_scope`
//! / `sync_claim_scope` call, flag the write.
//!
//! Phase-3 ships heuristic-grade — full reachability requires the
//! whole-program call graph. TODO(phase-4): track the claim scope across
//! function boundaries via the persistent CPG store.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, collect_descendant_calls, enclosing_file_path, first_arg_text,
    location_from_node, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONCURRENT-FILE-CLAIM-BYPASS.
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
        "cc.concurrent.file_claim_bypass"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "write to shared `data/...` without FileClaimRegistry::sync_claim_scope"
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
    is_data_path(&arg)
}

/// True iff `arg` looks like a path in the shared `data/...` tree.
fn is_data_path(arg: &str) -> bool {
    let normalized = arg.replace('\\', "/");
    normalized.starts_with("data/")
        || normalized.starts_with("./data/")
        || normalized.contains("/data/")
}

fn emit(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let arg = first_arg_text(ctx.batch, call).unwrap_or_default();
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.file_claim_bypass",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("write to `{arg}` bypasses FileClaimRegistry::sync_claim_scope"),
        explanation: format!(
            "A shared `data/` tree requires every concurrent \
             write to acquire a claim via \
             `FileClaimRegistry::sync_claim_scope` first. Writing to \
             `{arg}` without one risks silent data corruption when two \
             agents touch the same path."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the write in `with FileClaimRegistry.sync_claim_scope(\"<scope>\"):` \
             (or the Rust / Go equivalent). If this is a bootstrap path \
             that legitimately runs single-threaded, document the \
             exception with a `# noqa: file-claim-bypass` comment."
                .into(),
        ),
        snippet: arg,
        weight: 5,
    }))
}
