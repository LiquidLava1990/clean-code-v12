//! `cc.deploy.k8s_latest_tag` — container `image:` pinned to `:latest`
//! or untagged.
//!
//! Closes kube-linter **latest-tag**. For each `image:` directive in a
//! K8s manifest, flag when the image reference uses the `:latest` tag,
//! has no tag at all, or is the bare implicit `:latest`. Digest-pinned
//! references (`@sha256:…`) are clean.
//!
//! Heuristic — line walker, single pass over the YAML body. Multiple
//! containers in one file emit independent findings.

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

/// Phase-8 probe: K8s container using `:latest` or implicit-latest tag.
#[derive(Debug, Default, Clone, Copy)]
pub struct K8sLatestTagRule;

impl Rule for K8sLatestTagRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.k8s_latest_tag"
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
        "K8s container image pinned to `:latest` or untagged (kube-linter latest-tag)"
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
            scan_images(text, &path, &mut out);
        }
        out
    }
}

fn scan_images(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(value) = strip_image_directive(trimmed) else {
            continue;
        };
        if let Some(reason) = classify_image(value) {
            let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(path, lineno, reason));
        }
    }
}

fn strip_image_directive(trimmed: &str) -> Option<&str> {
    let after_dash = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let value = after_dash.strip_prefix("image:")?.trim();
    let unquoted = value.trim_matches('"').trim_matches('\'');
    if unquoted.is_empty() || unquoted.starts_with('{') || unquoted.starts_with('$') {
        return None;
    }
    Some(unquoted)
}

fn classify_image(image: &str) -> Option<&'static str> {
    if image.contains('@') {
        return None;
    }
    let after_slash = image.rsplit_once('/').map_or(image, |(_, rest)| rest);
    if let Some((_, tag)) = after_slash.rsplit_once(':') {
        if tag == "latest" {
            return Some("image pinned to `:latest`");
        }
        return None;
    }
    Some("image has no explicit tag (implicit `:latest`)")
}

fn emit(path: &Utf8PathBuf, lineno: u32, reason: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.k8s_latest_tag",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "K8s manifest `{}:{lineno}` uses unpinned image ({reason})",
            path.as_str()
        ),
        explanation: format!(
            "Container declared at `{}:{lineno}` has {reason}. \
             Rolling restarts pull a new digest from the registry, so \
             two replicas of the same Deployment can run different \
             code with no manifest change. Detection mirrors \
             kube-linter's `latest-tag` rule.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pin the image to a digest \
             (`image: registry/app@sha256:abcd…`) or at minimum to a \
             versioned tag (`image: registry/app:1.4.2`). Pair with \
             `imagePullPolicy: IfNotPresent` to keep workloads stable \
             during registry outages."
                .into(),
        ),
        snippet: format!("image directive @ {lineno} :: {reason}"),
        weight: 3,
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
        K8sLatestTagRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    fn manifest_with_image(image_line: &str) -> Vec<u8> {
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
        {image_line}
"
        )
        .into_bytes()
    }

    #[test]
    fn flags_explicit_latest() {
        let body = manifest_with_image("image: nginx:latest");
        let findings = run("a.yaml", &body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.k8s_latest_tag");
    }

    #[test]
    fn flags_implicit_latest() {
        let body = manifest_with_image("image: nginx");
        let findings = run("a.yaml", &body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
    }

    #[test]
    fn silent_when_pinned() {
        let body = manifest_with_image("image: nginx:1.27.4");
        assert!(run("a.yaml", &body).is_empty());
    }

    #[test]
    fn silent_when_digest_pinned() {
        let digest = "sha256:beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";
        let body = manifest_with_image(&format!("image: nginx@{digest}"));
        assert!(run("a.yaml", &body).is_empty());
    }
}
