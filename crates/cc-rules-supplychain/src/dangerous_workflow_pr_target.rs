//! `cc.supplychain.dangerous_workflow_pr_target` — `pull_request_target`
//! plus a checkout of the PR head.
//!
//! `pull_request_target` runs in the context of the *base* repository
//! with full secrets, but if the workflow then checks out the PR's head
//! ref/sha, attacker-controlled code executes inside that privileged
//! context. This is the canonical "GitHub Actions RCE" pattern documented
//! by the Scorecard `Dangerous-Workflow` control.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_workflow_path, location_for_file, SupplyChainFindingBlueprint,
};

/// Family-32 probe R-SUPPLYCHAIN-DANGEROUS-WORKFLOW-PR-TARGET.
#[derive(Debug, Default, Clone, Copy)]
pub struct DangerousWorkflowPrTargetRule;

const HEAD_REF_TOKENS: &[&str] = &[
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
];

impl Rule for DangerousWorkflowPrTargetRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.dangerous_workflow_pr_target"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "pull_request_target workflow checks out untrusted PR head — RCE risk"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(raw) = string_prop(ctx.batch, file_id, "path") else {
        return;
    };
    let path = Utf8PathBuf::from(raw);
    if !is_workflow_path(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if !text.contains("pull_request_target") {
        return;
    }
    if !mentions_head_checkout(text) {
        return;
    }
    out.push(emit(&path));
}

/// True when the workflow text contains both a `checkout`-style action
/// reference AND a head-ref expression. Both must coexist for the
/// finding — `pull_request_target` alone is fine if no checkout happens.
fn mentions_head_checkout(text: &str) -> bool {
    let has_checkout = text.contains("actions/checkout") || text.contains("checkout@");
    let has_head_ref = HEAD_REF_TOKENS.iter().any(|t| text.contains(t));
    has_checkout && has_head_ref
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.dangerous_workflow_pr_target",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "Workflow `{}` checks out PR head under `pull_request_target`",
            path.as_str()
        ),
        explanation: format!(
            "`{}` triggers on `pull_request_target` (which runs with the \
             base repo's secrets) AND checks out the PR's head sha/ref. \
             The PR can ship a malicious `Makefile`, `package.json` script, \
             or workflow patch that executes inside the privileged context \
             — full secret exfiltration. This is the textbook \"GitHub \
             Actions RCE\" Scorecard `Dangerous-Workflow` control flags.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Either: (a) switch the trigger to `pull_request` (untrusted \
             code stays in the unprivileged sandbox); or (b) keep \
             `pull_request_target` but check out the BASE ref \
             (`${{ github.ref }}`) and never the PR head; or (c) split \
             into two workflows — privileged jobs read the PR via the API, \
             unprivileged jobs run the PR code."
                .into(),
        ),
        snippet: format!(
            "pull_request_target + checkout PR head in {}",
            path.as_str()
        ),
        weight: 5,
    })
}
