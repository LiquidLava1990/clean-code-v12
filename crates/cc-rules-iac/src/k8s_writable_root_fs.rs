//! `cc.deploy.k8s_writable_root_fs` — container without
//! `securityContext.readOnlyRootFilesystem: true`.
//!
//! Closes kube-linter **read-only-root-fs**. Walks every K8s manifest
//! and flags pods whose containers do not declare an explicit
//! read-only root filesystem. Writeable container roots let an
//! attacker drop binaries, modify `/etc/hosts`, or persist arbitrary
//! payloads through a process restart.

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

/// Phase-8 probe: K8s container missing `readOnlyRootFilesystem: true`.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sWritableRootFsRule;

impl Rule for K8sWritableRootFsRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.k8s_writable_root_fs"
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
        "K8s container missing `readOnlyRootFilesystem: true` (kube-linter read-only-root-fs)"
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
            if has_read_only_root(text) {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

fn has_read_only_root(text: &str) -> bool {
    text.lines().any(|l| {
        let trimmed = l.trim();
        trimmed.starts_with("readOnlyRootFilesystem:") && trimmed.contains("true")
    })
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.k8s_writable_root_fs",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "K8s workload `{}` does not declare `readOnlyRootFilesystem: true`",
            path.as_str()
        ),
        explanation: format!(
            "Manifest `{}` has no explicit \
             `securityContext.readOnlyRootFilesystem: true` on its \
             containers. A writeable root lets an attacker drop \
             binaries, edit `/etc/passwd`, or persist arbitrary \
             payloads inside the container's overlay layer until a \
             pod replacement. Detection mirrors kube-linter's \
             `read-only-root-fs` rule.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Per container, set:\n  securityContext:\n    \
             readOnlyRootFilesystem: true\n\nMount an `emptyDir` \
             volume on `/tmp` (or anywhere the app legitimately \
             writes) to keep ephemeral state working under a \
             read-only root."
                .into(),
        ),
        snippet: format!("{} :: missing readOnlyRootFilesystem=true", path.as_str()),
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
        K8sWritableRootFsRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_missing_readonly() {
        let body = b"apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
spec:
  template:
    spec:
      containers:
      - name: a
        image: nginx:1.27
";
        let findings = run("a.yaml", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.k8s_writable_root_fs");
    }

    #[test]
    fn silent_when_readonly_true() {
        let body = b"apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
spec:
  template:
    spec:
      containers:
      - name: a
        image: nginx:1.27
        securityContext:
          readOnlyRootFilesystem: true
";
        assert!(run("a.yaml", body).is_empty());
    }

    #[test]
    fn silent_when_not_a_k8s_manifest() {
        let body = b"foo:\n  bar: baz\n";
        assert!(run("a.yaml", body).is_empty());
    }
}
