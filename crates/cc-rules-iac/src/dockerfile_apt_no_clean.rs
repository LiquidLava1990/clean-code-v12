//! `cc.iac.dockerfile_apt_no_clean` — `apt-get install` without lists clean.
//!
//! Heuristic: a `RUN apt-get install …` step that doesn't `rm -rf
//! /var/lib/apt/lists/*` (or chain into an `apt-get clean`) bloats the
//! resulting image by ~40 MB of cached package metadata. Severity nit.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_dockerfile_path, is_iac_test_fixture, location_for_file, IacFindingBlueprint,
};

/// Family-29 probe R-IAC-DOCKERFILE-APT-NO-CLEAN.
#[derive(Debug, Default, Clone, Copy)]
pub struct DockerfileAptNoCleanRule;

const CLEAN_MARKERS: &[&str] = &["rm -rf /var/lib/apt/lists", "apt-get clean", "apt clean"];

impl Rule for DockerfileAptNoCleanRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.dockerfile_apt_no_clean"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "RUN apt-get install without `rm -rf /var/lib/apt/lists/*`"
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
            scan_with_continuations(text, &path, &mut out);
        }
        out
    }
}

/// Walk the file collapsing backslash-continued `RUN` lines into a
/// single logical statement, then check for the clean marker.
fn scan_with_continuations(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let mut buffer = String::new();
    let mut start_line: u32 = 0;
    for (idx, raw) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        let trimmed = raw.trim_end();
        let continued = trimmed.ends_with('\\');
        let payload = if continued {
            &trimmed[..trimmed.len() - 1]
        } else {
            trimmed
        };
        if buffer.is_empty() && payload.trim_start().starts_with("RUN ") {
            start_line = lineno;
        }
        if !buffer.is_empty() || payload.trim_start().starts_with("RUN ") {
            buffer.push_str(payload);
            buffer.push(' ');
        }
        if !continued && !buffer.is_empty() {
            if let Some(snippet) = check_apt(&buffer) {
                out.push(emit(path, start_line, snippet));
            }
            buffer.clear();
        }
    }
}

/// Returns `Some(snippet)` when `stmt` installs apt packages but never
/// cleans the apt cache.
fn check_apt(stmt: &str) -> Option<String> {
    if !stmt.contains("apt-get install") && !stmt.contains("apt install") {
        return None;
    }
    if CLEAN_MARKERS.iter().any(|m| stmt.contains(m)) {
        return None;
    }
    Some(
        stmt.split_whitespace()
            .take(8)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn emit(path: &Utf8PathBuf, lineno: u32, snippet: String) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.dockerfile_apt_no_clean",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`apt-get install` at `{}:{lineno}` doesn't clean the apt cache",
            path.as_str()
        ),
        explanation: format!(
            "Dockerfile `{}` line {lineno} runs `apt-get install` but does \
             not chain into `rm -rf /var/lib/apt/lists/*` or `apt-get \
             clean`. The package index lingers in the layer, bloating \
             the published image by ~40 MB of metadata that's only \
             useful at build time.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Append `&& rm -rf /var/lib/apt/lists/*` to the same `RUN` \
             instruction (cleaning in a later layer doesn't shrink the \
             image — every layer is immutable). Pair with \
             `--no-install-recommends` for further savings."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
