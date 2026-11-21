//! `cc.deploy.k8s_run_as_root` — Pod / Deployment / StatefulSet /
//! DaemonSet without `securityContext.runAsNonRoot: true` covering its
//! containers.
//!
//! Closes kube-linter **run-as-non-root**. Different from the existing
//! `k8s_no_security_context` probe in two ways:
//!
//! 1. Phase-8 contract requires the file-extension + apiVersion / kind
//!    guard.
//! 2. We accept either pod-level OR every container declaring
//!    `runAsNonRoot: true` — kube-linter is per-container, so a
//!    pod-level true value still closes the gate.
//!
//! Heuristic — line walker. We treat the manifest as one document
//! window; a single explicit `runAsNonRoot: true` anywhere in the
//! pod's `securityContext` (top-level or container-level) closes the
//! finding.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_test_file_path, is_yaml_path, location_for_file,
    looks_like_rule_pack_source, yaml_has_k8s_kind, yaml_looks_like_k8s_manifest,
    IacFindingBlueprint,
};

/// Phase-8 probe: K8s container running as root.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sRunAsRootRule;

impl Rule for K8sRunAsRootRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.k8s_run_as_root"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "K8s workload missing `runAsNonRoot: true` (kube-linter run-as-non-root)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_yaml_path(&path)
                || is_iac_test_fixture(&path)
                || is_test_file_path(&path)
                || looks_like_rule_pack_source(&path)
            {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if !yaml_looks_like_k8s_manifest(text) || !yaml_has_k8s_kind(text) {
                continue;
            }
            if has_run_as_non_root_true(text) {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

/// `true` when ANY `runAsNonRoot: true` appears, OR when an explicit
/// `runAsUser:` with a value > 0 closes the case.
fn has_run_as_non_root_true(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("runAsNonRoot:") && trimmed.contains("true") {
            return true;
        }
        if let Some(uid) = parse_run_as_user(trimmed) {
            if uid > 0 {
                return true;
            }
        }
    }
    false
}

fn parse_run_as_user(trimmed: &str) -> Option<u64> {
    let rest = trimmed.strip_prefix("runAsUser:")?;
    rest.trim().parse().ok()
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.k8s_run_as_root",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "K8s workload `{}` may run containers as UID 0 (no `runAsNonRoot: true`)",
            path.as_str()
        ),
        explanation: format!(
            "Manifest `{}` declares a workload without an explicit \
             `securityContext.runAsNonRoot: true` (and no `runAsUser` > \
             0). On the `restricted` PSP / pod-security tier the API \
             server rejects the pod; on permissive namespaces the \
             container inherits the image's last `USER` directive — \
             frequently UID 0. Detection mirrors kube-linter's \
             `run-as-non-root` rule.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add at the pod level:\n  securityContext:\n    \
             runAsNonRoot: true\n    runAsUser: 1000\n    fsGroup: \
             1000\n\n— or set the same fields per container if a \
             single workload mixes root-needing and root-free \
             containers."
                .into(),
        ),
        snippet: format!("{} :: missing runAsNonRoot=true", path.as_str()),
        weight: 4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use cc_config::RuleConfig;
    use cc_cpg::{CpgWriteBatch, NodeBuilder, Value};
    use cc_rules::{InMemorySourceTable, KernelMeta, ProjectFingerprint};

    fn run(path: &str, body: &[u8]) -> Vec<Finding> {
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::File)
                .with_prop("path", Value::String(path.to_owned()))
                .with_prop("language", Value::String("yaml".into())),
        );
        let source = InMemorySourceTable::new();
        source.insert(Utf8PathBuf::from(path), body.to_vec());
        let cfg = RuleConfig::default();
        let proj = ProjectFingerprint::empty();
        let kernel = KernelMeta::now();
        K8sRunAsRootRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    const PLAIN_DEPLOY: &[u8] = b"apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27
";

    #[test]
    fn flags_pod_without_run_as_non_root() {
        let findings = run("deploy.yaml", PLAIN_DEPLOY);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.k8s_run_as_root");
    }

    #[test]
    fn silent_when_run_as_non_root_true() {
        let body = b"apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
      - name: web
        image: nginx:1.27
";
        assert!(run("deploy.yaml", body).is_empty());
    }

    #[test]
    fn silent_when_run_as_user_nonzero() {
        let body = b"apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsUser: 1000
      containers:
      - name: web
        image: nginx:1.27
";
        assert!(run("deploy.yaml", body).is_empty());
    }
}
