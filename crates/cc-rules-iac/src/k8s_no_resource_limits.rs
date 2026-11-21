//! `cc.iac.k8s_no_resource_limits` — k8s workload without `resources.limits`.
//!
//! Heuristic: walk every `*.yaml` / `*.yml` file. If it declares a
//! `kind: Deployment` / `Pod` / `StatefulSet` / `DaemonSet` / `Job` /
//! `CronJob` document but does not contain a `resources:` block with a
//! `limits:` key, flag the file. Workloads without limits are noisy
//! neighbours and the first to be OOM-killed under cluster pressure.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_yaml_path, location_for_file, yaml_has_k8s_kind,
    IacFindingBlueprint,
};

/// Family-29 probe R-IAC-K8S-NO-RESOURCE-LIMITS.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sNoResourceLimitsRule;

impl Rule for K8sNoResourceLimitsRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.k8s_no_resource_limits"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "k8s workload missing `resources.limits` block"
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
            if has_resource_limits(text) {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

/// True iff `text` contains a `resources:` followed (within 40 lines)
/// by a `limits:` key. Phase-6 path-level detection only — close enough
/// to avoid false positives on workloads that only declare requests.
fn has_resource_limits(text: &str) -> bool {
    let mut window: u32 = 0;
    let mut in_resources = false;
    for line in text.lines() {
        if let Some(trimmed) = line.strip_prefix(' ') {
            let _ = trimmed;
        }
        if line.contains("resources:") {
            in_resources = true;
            window = 0;
            continue;
        }
        if in_resources {
            window = window.saturating_add(1);
            if line.contains("limits:") {
                return true;
            }
            if window > 40 {
                in_resources = false;
            }
        }
    }
    false
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.k8s_no_resource_limits",
        severity: Severity::Required,
        confidence: Confidence::new(0.75),
        location,
        headline: format!(
            "k8s workload `{}` has no `resources.limits` block",
            path.as_str()
        ),
        explanation: format!(
            "Manifest `{}` declares a workload without a `resources: \
             limits:` block. The pod will be admitted under the namespace \
             default (often unbounded) and competes for CPU + memory \
             with every other unbounded pod on the node — when pressure \
             hits, the kubelet picks an OOM victim that is hard to \
             predict.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add `resources:\n  requests: { cpu: …, memory: … }\n  \
             limits: { cpu: …, memory: … }` under each container. \
             Start from observed p95 + 30% headroom; tune via the \
             vertical-pod-autoscaler in recommendation mode."
                .into(),
        ),
        snippet: format!("{} :: missing resources.limits", path.as_str()),
        weight: 3,
    })
}
