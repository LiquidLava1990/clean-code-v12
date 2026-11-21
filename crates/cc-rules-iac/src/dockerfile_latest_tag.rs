//! `cc.iac.dockerfile_latest_tag` — base image pinned to `:latest` or unpinned.
//!
//! `FROM image:latest` and `FROM image` (no tag) both float the base
//! image, so reproducibility evaporates and cached layers silently drift.
//! Industry standard is to pin to a digest (`@sha256:…`) or at minimum
//! to a versioned tag (`:1.27-alpine`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_dockerfile_path, is_iac_test_fixture, location_for_file, IacFindingBlueprint,
};

/// Family-29 probe R-IAC-DOCKERFILE-LATEST-TAG.
#[derive(Debug, Default, Clone, Copy)]
pub struct DockerfileLatestTagRule;

impl Rule for DockerfileLatestTagRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.dockerfile_latest_tag"
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
        "Dockerfile FROM uses `:latest` or no tag — pin the version"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_dockerfile_path(&path) || is_iac_test_fixture(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            scan(text, &path, &mut out);
        }
        out
    }
}

fn scan(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if !trimmed.starts_with("FROM ") && !trimmed.starts_with("FROM\t") {
            continue;
        }
        let body = trimmed["FROM ".len()..].trim();
        if let Some(reason) = classify_from(body) {
            let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(path, lineno, trimmed, reason));
        }
    }
}

/// Returns `Some(reason)` when the `FROM` clause is unpinned.
fn classify_from(body: &str) -> Option<&'static str> {
    // Strip `--platform=...` / multi-stage `as <alias>`.
    let image = body
        .split_whitespace()
        .find(|tok| !tok.starts_with("--"))
        .unwrap_or(body);
    if image.contains('@') {
        // digest pin — best practice.
        return None;
    }
    // Last `:` separates host:port from tag — only treat as a tag when
    // the right side has no `/`.
    if let Some((_, tag)) = image.rsplit_once(':') {
        if tag.contains('/') {
            return Some("base image has no tag");
        }
        if tag == "latest" {
            return Some("base image pinned to `:latest`");
        }
        return None;
    }
    Some("base image has no tag")
}

fn emit(path: &Utf8PathBuf, lineno: u32, line: &str, reason: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.dockerfile_latest_tag",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("Dockerfile line {lineno}: {reason}"),
        explanation: format!(
            "Dockerfile `{}` line {lineno} ({reason}) lets the registry \
             swap the base layer at any future build. Reproducibility, \
             vulnerability provenance, and CI cache hits all break.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pin to a digest (`FROM image@sha256:…`) for full \
             reproducibility, or at minimum to a versioned tag \
             (`FROM image:1.27.4-alpine3.20`)."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 3,
    })
}
