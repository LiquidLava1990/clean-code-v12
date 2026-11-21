//! Internal helpers shared across Family-13 (deployment) probes.
//!
//! Re-implements the small set of traversal primitives every Family-13
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinDeployPack;

/// Probe-pack identity stamped on every Family-13 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinDeployPack::PACK_ID,
        BuiltinDeployPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "path").map(Utf8PathBuf::from);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property, falling
/// back to the start of the file when the property is missing.
pub(crate) fn location_from_node(batch: &CpgWriteBatch, id: NodeId, file: Utf8PathBuf) -> Location {
    let (start, end) = range_prop(batch, id, "range").map_or_else(
        || {
            let zero = Position::new(1, 1, 0);
            (zero, zero)
        },
        |r| {
            (
                Position::new(r.start.line, r.start.column, r.start.offset),
                Position::new(r.end.line, r.end.column, r.end.offset),
            )
        },
    );
    Location {
        file,
        start,
        end,
        node_id: Some(cc_finding::NodeId::new(id.get().to_string())),
        function_qualified_name: string_prop(batch, id, "name").map(str::to_owned),
    }
}

/// True iff `path` looks like a test file across the four supported
/// languages.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if has_test_segment(&lower) {
        return true;
    }
    match path.file_stem() {
        Some(stem) => is_test_stem(&stem.to_ascii_lowercase()),
        None => false,
    }
}

fn has_test_segment(lower: &str) -> bool {
    lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
}

fn is_test_stem(stem_lower: &str) -> bool {
    stem_lower == "tests"
        || stem_lower == "test"
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] — every pack
/// uses the same canonical merge logic so substring needles see a
/// uniform haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
}

/// Destructive filesystem-call needles. Substring match against
/// [`callee_text`] — covers Python, Rust, Node.js, and Go.
pub(crate) const DESTRUCTIVE_CALLEES: &[&str] = &[
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "fs.unlinkSync",
    "fs.rmSync",
    "fs.rmdirSync",
    "fs.unlink",
    "fs.rm",
    "std::fs::remove_dir_all",
    "std::fs::remove_file",
    "remove_dir_all",
    "remove_file",
    "os.RemoveAll",
    "os.Remove",
];

/// Feature-flag library callees. Substring match — used to suppress
/// `cc.deploy.missing_feature_flag` when a risky-name function actually
/// guards itself with a flag.
pub(crate) const FLAG_LIBRARY_CALLEES: &[&str] = &[
    "feature_flag",
    "is_enabled",
    "isEnabled",
    "flag.evaluate",
    "flags.evaluate",
    "unleash",
    "Unleash",
    "LaunchDarkly",
    "ldclient",
    "growthbook",
    "GrowthBook",
    "split.getTreatment",
    "Statsig",
];

/// Function-name prefixes that the codebase has self-classified as risky
/// (experimental, beta, new, v2). Lowercased.
pub(crate) const RISKY_NAME_PREFIXES: &[&str] = &["experimental_", "beta_", "new_", "v2_"];

/// Inputs every Family-13 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct DeployFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.deploy.no_rollback_path"`.
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

/// Build a complete [`Finding`] from a [`DeployFindingBlueprint`].
pub(crate) fn build_finding(blueprint: DeployFindingBlueprint) -> Finding {
    let DeployFindingBlueprint {
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
        .expect("Family-13 finding builder receives all required fields")
}

/// True iff `path` is a source file inside a rule-pack crate. Used by
/// every Family-13 probe to skip its own detector strings (the pack
/// embeds the literal needle list — would otherwise self-flag).
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}
