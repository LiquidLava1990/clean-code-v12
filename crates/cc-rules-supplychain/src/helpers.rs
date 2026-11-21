//! Internal helpers shared across Family-32 probes.
//!
//! Re-implements the small set of traversal primitives every Family-32
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates.

use camino::Utf8PathBuf;
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};

use crate::pack::BuiltinSupplyChainPack;

/// Probe-pack identity stamped on every Family-32 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinSupplyChainPack::PACK_ID,
        BuiltinSupplyChainPack::PACK_SEMVER,
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

/// GitHub Actions workflow path patterns (substring tests against
/// `/`-normalised path).
pub(crate) const WORKFLOW_PATH_PATTERNS: &[&str] = &[".github/workflows/"];

/// True iff `path` is a `.github/workflows/*.yml` (or `.yaml`) file.
#[must_use]
pub(crate) fn is_workflow_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if !WORKFLOW_PATH_PATTERNS.iter().any(|p| lower.contains(p)) {
        return false;
    }
    lower.ends_with(".yml") || lower.ends_with(".yaml")
}

/// Manifest filenames that demand a Dependabot / Renovate config.
pub(crate) const MANIFEST_FILES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "go.mod",
    "requirements.txt",
    "pyproject.toml",
    "Gemfile",
    "pom.xml",
    "build.gradle",
];

/// Governance files whose absence Scorecard / GitHub repo policy flags.
/// `(rule_concept, &[acceptable_paths])`.
pub(crate) const GOVERNANCE_FILES_REQUIRED: &[(&str, &[&str])] = &[
    (
        "dependabot",
        &[".github/dependabot.yml", ".github/dependabot.yaml"],
    ),
    (
        "codeowners",
        &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"],
    ),
    (
        "security_md",
        &["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"],
    ),
];

/// True iff `s` is exactly 40 hex characters (a SHA-1 commit id). Pure
/// ASCII check — no allocation.
#[must_use]
pub(crate) fn is_sha1_hex(s: &str) -> bool {
    if s.len() != 40 {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True iff any path in `paths` ends with one of the `candidates`
/// basenames (case-sensitive — repo-policy filenames are conventional).
#[must_use]
pub(crate) fn any_path_matches(paths: &[Utf8PathBuf], candidates: &[&str]) -> bool {
    paths.iter().any(|p| {
        let normalised = p.as_str().replace('\\', "/");
        candidates
            .iter()
            .any(|c| normalised == *c || normalised.ends_with(&format!("/{c}")))
    })
}

/// True iff `paths` contains any manifest in [`MANIFEST_FILES`].
#[must_use]
pub(crate) fn has_any_manifest(paths: &[Utf8PathBuf]) -> bool {
    paths
        .iter()
        .filter_map(|p| p.file_name())
        .any(|name| MANIFEST_FILES.iter().any(|m| *m == name))
}

/// Inputs every Family-32 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct SupplyChainFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.supplychain.unpinned_action"`.
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

/// Build a complete [`Finding`] from a [`SupplyChainFindingBlueprint`].
pub(crate) fn build_finding(blueprint: SupplyChainFindingBlueprint) -> Finding {
    let SupplyChainFindingBlueprint {
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
        .category(Category::Deps)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-32 finding builder receives all required fields")
}
