//! `cc.iac.dockerfile_no_user` — Dockerfile that runs as root.
//!
//! Heuristic: walk every [`NodeKind::File`] whose path is a Dockerfile.
//! Read the source bytes; if no `USER ` directive (other than
//! `USER root` / `--user=root`) is present, flag the file. Containers
//! inheriting the default UID 0 expand the blast radius of any RCE.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_dockerfile_path, is_iac_test_fixture, location_for_file, IacFindingBlueprint,
};

/// Family-29 probe R-IAC-DOCKERFILE-NO-USER.
#[derive(Debug, Default, Clone, Copy)]
pub struct DockerfileNoUserRule;

impl Rule for DockerfileNoUserRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.dockerfile_no_user"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Dockerfile has no USER directive — container runs as root"
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
            if let Some(reason) = classify(text) {
                out.push(emit(&path, reason));
            }
        }
        out
    }
}

/// Returns `Some(reason)` when the Dockerfile leaves the container
/// running as root, `None` when a non-root `USER` is set.
fn classify(text: &str) -> Option<&'static str> {
    let mut last_user_root = false;
    let mut saw_non_root_user = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("USER ") && !trimmed.starts_with("USER\t") {
            continue;
        }
        let arg = trimmed["USER ".len()..].trim();
        if arg.eq_ignore_ascii_case("root") || arg == "0" {
            last_user_root = true;
            saw_non_root_user = false;
        } else if !arg.is_empty() {
            saw_non_root_user = true;
            last_user_root = false;
        }
    }
    if saw_non_root_user {
        return None;
    }
    if last_user_root {
        return Some("explicit `USER root`");
    }
    Some("no `USER` directive")
}

fn emit(path: &Utf8PathBuf, reason: &'static str) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.dockerfile_no_user",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("Dockerfile `{}` runs as root ({reason})", path.as_str()),
        explanation: format!(
            "Dockerfile `{}` has {reason}, so the container's main process \
             inherits UID 0. Any RCE inside the container becomes a root \
             RCE; mounted host paths, capability surfaces, and downstream \
             k8s `runAsNonRoot: true` checks all degrade.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a `RUN groupadd … && useradd …` step (or `adduser` on \
             Alpine) and finish the Dockerfile with `USER appuser` before \
             the entrypoint. If a build step legitimately needs root, set \
             `USER root` only for that span and switch back."
                .into(),
        ),
        snippet: format!("Dockerfile :: {reason}"),
        weight: 4,
    })
}
