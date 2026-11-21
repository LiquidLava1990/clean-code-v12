//! `cc.deploy.k8s_privileged` — container with `securityContext.privileged: true`.
//!
//! Closes kube-linter **privileged-container**. A privileged container
//! shares every capability with the kernel (essentially `--privileged`
//! in Docker) — `CAP_SYS_ADMIN`, raw block-device access, the host's
//! cgroup namespace. Any RCE inside that container is functionally a
//! node compromise. The kube-linter rule treats this as the highest-
//! signal violation in the entire pack; we mirror that with
//! confidence = 0.98.

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

/// Phase-8 probe: detect K8s container with `privileged: true`.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sPrivilegedRule;

impl Rule for K8sPrivilegedRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.k8s_privileged"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.98)
    }
    fn description(&self) -> &'static str {
        "K8s container runs with `privileged: true` (kube-linter privileged-container)"
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
            scan_privileged(text, &path, &mut out);
        }
        out
    }
}

fn scan_privileged(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("privileged:") {
            continue;
        }
        let value = trimmed["privileged:".len()..].trim();
        if value.starts_with("true") {
            let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(path, lineno));
        }
    }
}

fn emit(path: &Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.k8s_privileged",
        severity: Severity::Required,
        confidence: Confidence::new(0.98),
        location,
        headline: format!(
            "K8s container at `{}:{lineno}` declares `privileged: true`",
            path.as_str()
        ),
        explanation: format!(
            "A privileged container at `{}:{lineno}` shares every \
             kernel capability with the host. Any RCE inside the \
             container becomes a node compromise — host filesystem \
             reads, raw block-device access, and the ability to \
             schedule arbitrary kernel modules. Detection mirrors \
             kube-linter's `privileged-container` rule.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Remove `privileged: true`. If the workload genuinely \
             needs a specific capability (e.g. `NET_ADMIN` for a CNI \
             agent), add it explicitly via:\n  securityContext:\n    \
             capabilities:\n      add: [\"NET_ADMIN\"]\n      drop: \
             [\"ALL\"]\n\nNever ship privileged containers in \
             production application pods."
                .into(),
        ),
        snippet: format!("privileged: true @ {lineno}"),
        weight: 10,
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
        K8sPrivilegedRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    fn manifest_with_security(setting: &str) -> Vec<u8> {
        format!(
            "apiVersion: apps/v1
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
          {setting}
"
        )
        .into_bytes()
    }

    #[test]
    fn flags_privileged_true() {
        let body = manifest_with_security("privileged: true");
        let findings = run("a.yaml", &body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.k8s_privileged");
    }

    #[test]
    fn silent_when_privileged_false() {
        let body = manifest_with_security("privileged: false");
        assert!(run("a.yaml", &body).is_empty());
    }

    #[test]
    fn silent_when_no_securitycontext() {
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
        assert!(run("a.yaml", body).is_empty());
    }
}
