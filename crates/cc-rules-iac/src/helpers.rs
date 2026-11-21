//! Internal helpers shared across Family-29 probes.
//!
//! Re-implements the small set of traversal primitives every Family-29
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates.

use camino::Utf8PathBuf;
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};

use crate::pack::BuiltinIacPack;

/// Probe-pack identity stamped on every Family-29 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinIacPack::PACK_ID,
        BuiltinIacPack::PACK_SEMVER,
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

/// Inputs every Family-29 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct IacFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.iac.dockerfile_no_user"`.
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

/// Build a complete [`Finding`] from an [`IacFindingBlueprint`].
pub(crate) fn build_finding(blueprint: IacFindingBlueprint) -> Finding {
    let IacFindingBlueprint {
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
        .category(Category::Deploy)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-29 finding builder receives all required fields")
}

/// True iff `path` looks like a test fixture rather than real IaC. We
/// deliberately avoid skipping `tests/` for this pack — IaC packs often
/// live under integration test dirs — but we DO skip files whose stem
/// looks like a test name (`*_test.yml`, `test_*.tf`).
#[must_use]
pub(crate) fn is_iac_test_fixture(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if lower.contains("/fixtures/") || lower.contains("/test-fixtures/") {
        return true;
    }
    let Some(stem) = path.file_stem().map(str::to_ascii_lowercase) else {
        return false;
    };
    stem.starts_with("test_") || stem.ends_with("_test") || stem.ends_with(".test")
}

// ---------- path classifiers -----------------------------------------------

/// True iff `path` is a Dockerfile (basename `Dockerfile`, `Dockerfile.*`,
/// or `*.dockerfile`).
#[must_use]
pub(crate) fn is_dockerfile_path(path: &Utf8PathBuf) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    if name == "Dockerfile" || name.starts_with("Dockerfile.") {
        return true;
    }
    name.to_ascii_lowercase().ends_with(".dockerfile")
}

/// True iff `path` is a YAML file (`.yml` / `.yaml`).
#[must_use]
pub(crate) fn is_yaml_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().to_ascii_lowercase();
    lower.ends_with(".yml") || lower.ends_with(".yaml")
}

/// True iff `path` is a Terraform / OpenTofu HCL file.
#[must_use]
pub(crate) fn is_terraform_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().to_ascii_lowercase();
    lower.ends_with(".tf") || lower.ends_with(".tofu")
}

/// True iff `path`'s basename is `Chart.yaml` (Helm chart manifest).
#[must_use]
pub(crate) fn is_helm_chart_yaml(path: &Utf8PathBuf) -> bool {
    path.file_name() == Some("Chart.yaml")
}

/// True iff `path`'s basename is the Helm chart lock companion.
#[must_use]
pub(crate) fn is_helm_chart_lock(path: &Utf8PathBuf) -> bool {
    path.file_name() == Some("Chart.lock")
}

/// True iff `path` is a `docker-compose.yml` / `compose.yaml` file.
#[must_use]
pub(crate) fn is_compose_path(path: &Utf8PathBuf) -> bool {
    let Some(name) = path.file_name().map(str::to_ascii_lowercase) else {
        return false;
    };
    matches!(
        name.as_str(),
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
    )
}

/// k8s `kind:` markers we audit for resource limits + security context.
pub(crate) const K8S_KINDS_REQUIRING_LIMITS: &[&str] = &[
    "kind: Deployment",
    "kind: Pod",
    "kind: StatefulSet",
    "kind: DaemonSet",
    "kind: Job",
    "kind: CronJob",
];

/// Terraform high-risk resource type names — destruction is unrecoverable.
pub(crate) const TF_HIGH_RISK_RESOURCES: &[&str] = &[
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "google_sql_database_instance",
    "azurerm_postgresql_server",
];

/// True iff at least one of the YAML `kind:` markers in
/// [`K8S_KINDS_REQUIRING_LIMITS`] appears in `text`.
#[must_use]
pub(crate) fn yaml_has_k8s_kind(text: &str) -> bool {
    K8S_KINDS_REQUIRING_LIMITS
        .iter()
        .any(|marker| text.contains(marker))
}

/// True iff `path` looks like a Phase-8 self-host hit — any source file
/// that lives under one of the kernel's `cc-rules-*` crates. The IaC
/// probes scan for needle strings that occur in their own
/// remediation / docstring text; without this guard the kernel
/// self-host run would emit one finding per probe per build.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let normalised = path.as_str().replace('\\', "/").to_ascii_lowercase();
    normalised.contains("/cc-rules-") || normalised.starts_with("crates/cc-rules-")
}

/// True iff `path` looks like a test file across the supported IaC
/// shapes. Mirrors `cc-rules-tier0::is_test_file_path` so Phase-8
/// probes share the same skip semantics as Tier-0 probes.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
    {
        return true;
    }
    let Some(stem) = path.file_stem().map(str::to_ascii_lowercase) else {
        return false;
    };
    stem == "tests"
        || stem == "test"
        || stem.starts_with("test_")
        || stem.ends_with("_test")
        || stem.ends_with(".test")
        || stem.ends_with(".spec")
}

/// Cheap top-of-file scan: does `text` look like a Kubernetes manifest?
///
/// Per Phase-8 contract, K8s probes only fire on YAML whose top-level
/// content names both `apiVersion:` AND `kind:`. The check is
/// substring-based to keep the parser footprint tiny — the existing
/// `yaml_has_k8s_kind` already handles the kind whitelist; this helper
/// is the cheaper extension-guard variant useful for probes that
/// accept any kind.
#[must_use]
pub(crate) fn yaml_looks_like_k8s_manifest(text: &str) -> bool {
    let mut saw_api_version = false;
    let mut saw_kind = false;
    for line in text.lines().take(200) {
        let trimmed = line.trim_start();
        if trimmed.starts_with("apiVersion:") {
            saw_api_version = true;
        }
        if trimmed.starts_with("kind:") {
            saw_kind = true;
        }
        if saw_api_version && saw_kind {
            return true;
        }
    }
    false
}

/// True iff `path` ends with `.tf` or `.tf.json` (Phase-8 contract).
/// `is_terraform_path` accepts `.tofu` too, which Phase-8 probes also
/// honour, but we keep both shapes here for clarity.
#[must_use]
pub(crate) fn is_terraform_phase8_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().to_ascii_lowercase();
    lower.ends_with(".tf") || lower.ends_with(".tf.json") || lower.ends_with(".tofu")
}
