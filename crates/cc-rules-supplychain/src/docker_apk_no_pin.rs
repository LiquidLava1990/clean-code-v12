//! `cc.supplychain.docker_apk_no_pin` — Dockerfile `apk add <pkg>`
//! without a `<pkg>=<version>` pin.
//!
//! Heuristic: walk every [`NodeKind::File`] whose basename is
//! `Dockerfile` (or starts with `Dockerfile.`). Scan source bytes
//! line-by-line for `RUN apk add ...` / `RUN apk --no-cache add ...`
//! and flag any package token that lacks `=<version>`. Mirrors
//! Hadolint DL3018: an unpinned alpine package re-resolves on every
//! image build, so the image is non-reproducible by definition.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, location_for_file, SupplyChainFindingBlueprint};

/// Family-32 probe R-SUPPLYCHAIN-DOCKER-APK-NO-PIN.
#[derive(Debug, Default, Clone, Copy)]
pub struct DockerApkNoPinRule;

impl Rule for DockerApkNoPinRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.docker_apk_no_pin"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "Dockerfile `apk add <pkg>` without `<pkg>=<version>` pin (Hadolint DL3018)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(raw) = string_prop(ctx.batch, file_id, "path") else {
        return;
    };
    let path = Utf8PathBuf::from(raw);
    if !is_dockerfile(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if let Some(unpinned) = first_unpinned_apk_pkg(line) {
            let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(&path, line_no, line.trim(), unpinned));
        }
    }
}

/// True iff `path` looks like a Dockerfile by the conventional naming
/// (`Dockerfile`, `Dockerfile.<variant>`, `<name>.Dockerfile`).
fn is_dockerfile(path: &Utf8PathBuf) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    name == "Dockerfile" || name.starts_with("Dockerfile.") || name.ends_with(".Dockerfile")
}

/// If the line is a `RUN apk add ...` and at least one package token is
/// not pinned with `=`, return the offending token. Returns `None` for
/// non-`apk add` lines and for fully-pinned ones.
fn first_unpinned_apk_pkg(line: &str) -> Option<String> {
    let upper = line.to_ascii_uppercase();
    if !upper.contains("RUN") || !line.contains("apk") {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    if !lower.contains("apk add") && !lower.contains("apk --no-cache add") {
        return None;
    }
    // Tokenise after the literal `add`. Anything that is a flag (`-X`,
    // `--foo`) or a shell continuation is skipped; everything else is a
    // package and must contain `=`.
    let tail = line.split_once(" add ").map(|(_, t)| t)?;
    for tok in tail.split_whitespace() {
        if tok.starts_with('-') || tok == "\\" || tok.is_empty() {
            continue;
        }
        if tok.contains('=') {
            continue;
        }
        return Some(tok.to_owned());
    }
    None
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str, pkg: String) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.docker_apk_no_pin",
        severity: Severity::Nit,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("`apk add {pkg}` is not pinned (Hadolint DL3018)"),
        explanation: format!(
            "`{}` line {line_no} runs `apk add {pkg}` without `={pkg}=<ver>`. \
             The image rebuild silently picks up whichever Alpine repo \
             version is current at build time — two builds of the same \
             Dockerfile can ship different binaries. Hadolint DL3018 \
             documents this as a reproducibility hole.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{pkg}` with `{pkg}=<exact-version>` (look up the \
             current Alpine package version with `apk policy {pkg}` in a \
             throwaway container). Re-bump deliberately when you've \
             reviewed the changelog."
        )),
        snippet: line.to_owned(),
        weight: 1,
    })
}
