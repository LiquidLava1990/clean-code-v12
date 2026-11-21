//! `cc.ci.lockfile_uncommitted` — manifest with no companion lockfile.
//!
//! Heuristic: collect every [`NodeKind::File`] basename in the batch.
//! If a manifest basename (`package.json`, `requirements.txt`,
//! `pyproject.toml`, `Cargo.toml`, `go.mod`) is present but NONE of its
//! lockfile alternatives are present in the same batch, flag the
//! manifest. An uncommitted lockfile lets transitive dependencies float
//! between developer machines and CI, which is the textbook reproducibility
//! hole.

use std::collections::BTreeSet;

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, location_for_file, CiFindingBlueprint, MANIFEST_LOCKFILE_PAIRS,
};

/// Family-17 probe R-CI-LOCKFILE-UNCOMMITTED.
#[derive(Debug, Default, Clone, Copy)]
pub struct LockfileUncommittedRule;

impl Rule for LockfileUncommittedRule {
    fn rule_id(&self) -> &'static str {
        "cc.ci.lockfile_uncommitted"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ci
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "manifest file present but its lockfile is missing"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let paths = collect_paths(ctx);
        let basenames = basenames(&paths);
        let mut out = Vec::new();
        for path in &paths {
            if let Some(reason) = orphan_manifest(path, &basenames) {
                out.push(emit(path, reason));
            }
        }
        out
    }
}

fn collect_paths(ctx: &RuleContext<'_>) -> Vec<Utf8PathBuf> {
    nodes_of_kind(ctx.batch, NodeKind::File)
        .filter_map(|node| string_prop(ctx.batch, node.id, "path").map(Utf8PathBuf::from))
        .collect()
}

fn basenames(paths: &[Utf8PathBuf]) -> BTreeSet<String> {
    paths
        .iter()
        .filter_map(|p| p.file_name().map(str::to_owned))
        .collect()
}

/// Returns the lockfile basenames the manifest expects when none are
/// present, or `None` when the manifest is satisfied or `path` is not a
/// recognised manifest at all.
fn orphan_manifest(
    path: &Utf8PathBuf,
    basenames: &BTreeSet<String>,
) -> Option<&'static [&'static str]> {
    let name = path.file_name()?;
    let entry = MANIFEST_LOCKFILE_PAIRS
        .iter()
        .find(|(manifest, _)| *manifest == name)?;
    let (_, lockfiles) = *entry;
    if lockfiles.iter().any(|l| basenames.contains(*l)) {
        return None;
    }
    Some(lockfiles)
}

fn emit(path: &Utf8PathBuf, lockfiles: &'static [&'static str]) -> Finding {
    let location = location_for_file(path.clone(), 1);
    let candidates = lockfiles.join(" / ");
    build_finding(CiFindingBlueprint {
        rule_id: "cc.ci.lockfile_uncommitted",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("Manifest `{}` has no committed lockfile", path.as_str()),
        explanation: format!(
            "Manifest `{}` is present but none of its lockfiles ({candidates}) \
             are committed. Transitive dependency versions can drift between \
             developer machines, CI, and production whenever the manifest \
             is re-resolved, which makes builds non-reproducible and security \
             advisories impossible to audit precisely.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Run the package manager's lock command (e.g. `npm install`, \
             `cargo generate-lockfile`, `poetry lock`, `go mod tidy`) and \
             commit the resulting lockfile ({candidates}) alongside the \
             manifest."
        )),
        snippet: path.as_str().to_owned(),
        weight: 4,
    })
}
