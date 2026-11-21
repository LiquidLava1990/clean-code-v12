//! Internal helpers shared across Family-17 probes.
//!
//! Re-implements the small set of traversal primitives every Family-17
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates.

use camino::Utf8PathBuf;
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};

use crate::pack::BuiltinCiPack;

/// Probe-pack identity stamped on every Family-17 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinCiPack::PACK_ID,
        BuiltinCiPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Build a [`Location`] anchored at the start of `file` on `line`.
#[must_use]
pub(crate) fn location_for_file(file: Utf8PathBuf, line: u32) -> Location {
    let pos = Position::new(line.max(1), 1, 0);
    Location {
        file,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    }
}

/// CI workflow path globs (substring tests against `/`-normalised path).
pub(crate) const CI_PATH_PATTERNS: &[&str] = &[
    ".github/workflows/",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".circleci/config.yml",
];

/// True iff `path` looks like a CI workflow definition.
#[must_use]
pub(crate) fn is_ci_workflow_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if !CI_PATH_PATTERNS.iter().any(|p| lower.contains(p)) {
        return false;
    }
    if lower.contains(".github/workflows/") {
        return lower.ends_with(".yml") || lower.ends_with(".yaml");
    }
    true
}

/// Required CI-step keywords. A workflow that mentions zero of these is
/// a probable misconfiguration.
pub(crate) const REQUIRED_STEP_KEYWORDS: &[&str] =
    &["lint", "test", "typecheck", "type-check", "type_check"];

/// `(manifest_basename, &[lockfile_basenames])` pairs. A manifest
/// without ANY of its lockfile alternatives present is flagged.
pub(crate) const MANIFEST_LOCKFILE_PAIRS: &[(&str, &[&str])] = &[
    (
        "package.json",
        &["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    ),
    ("requirements.txt", &["requirements.lock"]),
    ("pyproject.toml", &["poetry.lock", "uv.lock", "pdm.lock"]),
    ("Cargo.toml", &["Cargo.lock"]),
    ("go.mod", &["go.sum"]),
];

/// Inputs every Family-17 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct CiFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.ci.missing_step"`.
    pub rule_id: &'static str,
    /// Severity to stamp on the finding.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the issue manifests.
    pub location: Location,
    /// One-line headline shown first in any sink.
    pub headline: String,
    /// Multi-line explanation covering what + why.
    pub explanation: String,
    /// Concrete remediation guidance the user can act on.
    pub remediation: Remediation,
    /// Source-code snippet anchoring the finding (may be empty).
    pub snippet: String,
    /// Blocking-debt weight for score impact.
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`CiFindingBlueprint`].
pub(crate) fn build_finding(blueprint: CiFindingBlueprint) -> Finding {
    let CiFindingBlueprint {
        rule_id,
        severity,
        confidence,
        location,
        headline,
        explanation,
        remediation,
        snippet,
        weight,
    } = blueprint;
    let evidence = Evidence::from_snippet(snippet);
    let message = ActionableMessage::new(headline, explanation, remediation);
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Ci)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-17 finding builder receives all required fields")
}
