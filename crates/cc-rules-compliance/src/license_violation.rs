//! `cc.compliance.license_violation` — GPL-bearing license file
//! coexisting with a non-GPL top-level license.
//!
//! Heuristic: walk every [`NodeKind::File`] node whose path matches a
//! [`LICENSE_FILE_PATTERNS`](crate::helpers::LICENSE_FILE_PATTERNS)
//! entry. Read the file bytes from the source table, check for any
//! GPL marker (see [`GPL_MARKERS`](crate::helpers::GPL_MARKERS)).
//!
//! Phase-5 simplification: only flag when at least one GPL-bearing
//! license file coexists with at least one non-GPL license file in
//! the same batch — cross-license conflict is heuristic. Full
//! resolution requires a project-fingerprint declared SPDX expression
//! across `Cargo.toml` / `package.json` / `pyproject.toml`, which is
//! Phase-6 work.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_license_file, location_for_file, ComplianceFindingBlueprint, GPL_MARKERS,
};

/// Family-21 probe R-LICENSE-VIOLATION.
#[derive(Debug, Default, Clone, Copy)]
pub struct LicenseViolationRule;

impl Rule for LicenseViolationRule {
    fn rule_id(&self) -> &'static str {
        "cc.compliance.license_violation"
    }
    fn category(&self) -> Category {
        Category::Compliance
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "GPL-bearing LICENSE file coexists with a non-GPL LICENSE in the same project"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let buckets = collect_license_buckets(ctx);
        if buckets.gpl.is_empty() || buckets.non_gpl.is_empty() {
            return Vec::new();
        }
        emit_findings(&buckets)
    }
}

#[derive(Debug, Default)]
struct LicenseBuckets {
    gpl: Vec<Utf8PathBuf>,
    non_gpl: Vec<Utf8PathBuf>,
}

fn collect_license_buckets(ctx: &RuleContext<'_>) -> LicenseBuckets {
    let mut buckets = LicenseBuckets::default();
    for node in nodes_of_kind(ctx.batch, NodeKind::File) {
        let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
            continue;
        };
        let path = Utf8PathBuf::from(raw);
        if !is_license_file(&path) {
            continue;
        }
        let bytes = ctx.source.get(path.as_path());
        let text = std::str::from_utf8(bytes).unwrap_or("");
        if contains_gpl_marker(text) {
            buckets.gpl.push(path);
        } else {
            buckets.non_gpl.push(path);
        }
    }
    buckets
}

fn contains_gpl_marker(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    GPL_MARKERS.iter().any(|needle| upper.contains(needle))
}

fn emit_findings(buckets: &LicenseBuckets) -> Vec<Finding> {
    let non_gpl_summary = summarise_paths(&buckets.non_gpl);
    buckets
        .gpl
        .iter()
        .map(|path| build_one(path, &non_gpl_summary))
        .collect()
}

fn summarise_paths(paths: &[Utf8PathBuf]) -> String {
    let mut buf = String::new();
    for (idx, path) in paths.iter().enumerate() {
        if idx > 0 {
            buf.push_str(", ");
        }
        buf.push_str(path.as_str());
        if idx >= 2 {
            buf.push('…');
            break;
        }
    }
    buf
}

fn build_one(gpl_path: &Utf8PathBuf, non_gpl_summary: &str) -> Finding {
    let location = location_for_file(gpl_path.clone(), 1);
    build_finding(ComplianceFindingBlueprint {
        rule_id: "cc.compliance.license_violation",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{gpl_path}` is GPL-family alongside non-GPL license(s)"),
        explanation: format!(
            "`{gpl_path}` carries a GPL / AGPL / LGPL marker, but the project also \
             ships non-GPL license file(s) at {non_gpl_summary}. GPL is \
             copyleft and propagates: shipping it alongside MIT / Apache / BSD \
             without explicit dual-license notice is a compliance hazard."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Resolve the conflict: either remove the GPL-bearing dependency / \
             vendored source, document a clear dual-license relationship in \
             `LICENSE` + the package manifest, or migrate the project under \
             GPL-compatible terms. Update the SPDX expression in `Cargo.toml` / \
             `package.json` / `pyproject.toml` to match."
                .into(),
        ),
        snippet: gpl_path.as_str().to_owned(),
        weight: 3,
    })
}
