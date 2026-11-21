//! `cc.deploy.k8s_host_network` — pod spec declaring `hostNetwork: true`.
//!
//! Closes kube-linter **host-network**. A pod with `hostNetwork: true`
//! shares the node's network namespace: it sees every other pod's
//! traffic, can bind to privileged host ports, and bypasses
//! NetworkPolicy enforcement entirely. The detection mirrors
//! kube-linter's host-network rule.

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

/// Phase-8 probe: detect K8s pod spec with `hostNetwork: true`.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sHostNetworkRule;

impl Rule for K8sHostNetworkRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.k8s_host_network"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "K8s pod spec declares `hostNetwork: true` (kube-linter host-network)"
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
            scan_host_network(text, &path, &mut out);
        }
        out
    }
}

fn scan_host_network(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("hostNetwork:") {
            continue;
        }
        let value = trimmed["hostNetwork:".len()..].trim();
        if value.starts_with("true") {
            let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(path, lineno));
        }
    }
}

fn emit(path: &Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.k8s_host_network",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "K8s pod spec at `{}:{lineno}` declares `hostNetwork: true`",
            path.as_str()
        ),
        explanation: format!(
            "Pod spec at `{}:{lineno}` shares the node's network \
             namespace. The container can sniff every other pod's \
             traffic, bind privileged host ports (22, 80, 443), and \
             bypasses NetworkPolicy enforcement entirely — \
             NetworkPolicy is implemented at the pod-network layer \
             that `hostNetwork` short-circuits. Detection mirrors \
             kube-linter's `host-network` rule.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Remove `hostNetwork: true`. If the workload legitimately \
             needs host-port access (e.g. a node-local DNS cache), \
             scope the requirement: use `hostPort` on the specific \
             container port plus a NetworkPolicy that pins the \
             allowed peers, instead of joining the host namespace \
             outright."
                .into(),
        ),
        snippet: format!("hostNetwork: true @ {lineno}"),
        weight: 7,
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
        K8sHostNetworkRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    fn manifest_with_pod_setting(setting_line: &str) -> Vec<u8> {
        format!(
            "apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
spec:
  template:
    spec:
      {setting_line}containers:
      - name: a
        image: nginx:1.27
"
        )
        .into_bytes()
    }

    #[test]
    fn flags_host_network_true() {
        let body = manifest_with_pod_setting("hostNetwork: true\n      ");
        let findings = run("a.yaml", &body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.k8s_host_network");
    }

    #[test]
    fn silent_when_host_network_false() {
        let body = manifest_with_pod_setting("hostNetwork: false\n      ");
        assert!(run("a.yaml", &body).is_empty());
    }

    #[test]
    fn silent_when_absent() {
        let body = manifest_with_pod_setting("");
        assert!(run("a.yaml", &body).is_empty());
    }
}
