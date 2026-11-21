//! `cc.iac.k8s_no_security_context` — k8s workload without `runAsNonRoot: true`.
//!
//! Heuristic: any `*.yaml` / `*.yml` declaring a k8s workload kind that
//! does NOT contain `runAsNonRoot: true` is flagged. Kubernetes' own
//! pod-security admission webhooks enforce this on `restricted`-tier
//! namespaces; pre-empt the admission failure here.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_yaml_path, location_for_file, yaml_has_k8s_kind,
    IacFindingBlueprint,
};

/// Family-29 probe R-IAC-K8S-NO-SECURITY-CONTEXT.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sNoSecurityContextRule;

impl Rule for K8sNoSecurityContextRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.k8s_no_security_context"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "k8s workload missing `securityContext.runAsNonRoot: true`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_yaml_path(&path) || is_iac_test_fixture(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if !yaml_has_k8s_kind(text) {
                continue;
            }
            if has_run_as_non_root(text) {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

/// True iff `text` contains an explicit `runAsNonRoot: true` (the only
/// shape that satisfies pod-security `restricted`).
fn has_run_as_non_root(text: &str) -> bool {
    text.lines().any(|l| {
        let trimmed = l.trim();
        trimmed.starts_with("runAsNonRoot:") && trimmed.contains("true")
    })
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.k8s_no_security_context",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!(
            "k8s workload `{}` has no `runAsNonRoot: true`",
            path.as_str()
        ),
        explanation: format!(
            "Manifest `{}` does not pin `securityContext.runAsNonRoot: \
             true`. Pod-security admission on `restricted` namespaces \
             rejects this workload; on permissive namespaces the \
             container inherits whatever UID the image's last `USER` \
             directive selected (often root), expanding the blast \
             radius of any RCE.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a pod-level `securityContext:\n  runAsNonRoot: true\n  \
             runAsUser: 1000\n  seccompProfile: { type: \
             RuntimeDefault }` block, plus per-container \
             `allowPrivilegeEscalation: false` and `capabilities: { \
             drop: [\"ALL\"] }`."
                .into(),
        ),
        snippet: format!("{} :: missing securityContext.runAsNonRoot", path.as_str()),
        weight: 3,
    })
}
