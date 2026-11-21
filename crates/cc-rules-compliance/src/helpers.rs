//! Internal helpers shared across Family-21 (compliance) probes.
//!
//! Re-implements the small set of traversal primitives every Family-21
//! rule needs so the pack stays sibling-independent of the other
//! Family rule packs.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinCompliancePack;

/// Probe-pack identity stamped on every Family-21 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinCompliancePack::PACK_ID,
        BuiltinCompliancePack::PACK_SEMVER,
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

/// Build a [`Location`] anchored at the start of `path` — used when no
/// node range is available (whole-file findings).
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

/// True iff `path` looks like a test file across the four supported
/// languages.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if has_test_segment(&lower) {
        return true;
    }
    path.file_stem()
        .is_some_and(|stem| is_test_stem(&stem.to_ascii_lowercase()))
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

/// True iff `path` looks like the source of a rule-pack crate. Used to
/// keep `cc.compliance.pii_handling` from flagging itself when probes
/// embed PII-keyword needles in their detector tables.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// PII keyword table — lowercase substrings that indicate a field /
/// variable holds personally-identifiable data subject to GDPR / CCPA /
/// HIPAA-style protection.
pub(crate) const PII_KEYWORD_TABLE: &[&str] = &[
    "email",
    "ssn",
    "phone",
    "dob",
    "birthdate",
    "address",
    "passport",
    "credit_card",
    "tax_id",
    "national_id",
];

/// Audit-log call needles. Probes match callees against these to decide
/// whether a privileged operation has emitted an audit-log line.
pub(crate) const AUDIT_CALLEES: &[&str] = &[
    "audit_log",
    "audit.emit",
    "log.audit",
    "auditlog",
    "tracing::info!",
    "tracing::warn!",
];

/// Function-name prefixes / fragments that mark a function as a
/// privileged administrative operation requiring an audit log.
pub(crate) const PRIVILEGED_NAME_PATTERNS: &[&str] =
    &["admin_", "delete_", "update_role_", "grant_"];

/// Filename patterns that identify a license declaration file.
pub(crate) const LICENSE_FILE_PATTERNS: &[&str] = &[
    "license",
    "licence",
    "license.md",
    "licence.md",
    "license.txt",
    "licence.txt",
];

/// Hint substrings indicating an encryption-at-rest annotation has been
/// applied to a PII field. Conservative — any of these on the
/// surrounding write / type / decorator silences the probe.
pub(crate) const ENCRYPTION_HINTS: &[&str] = &[
    "encrypted",
    "encrypt",
    "kms",
    "vault",
    "secret",
    "cipher",
    "hashed",
    "@crypt",
];

/// GPL-family license markers — substring scan on license-file source.
pub(crate) const GPL_MARKERS: &[&str] = &["GNU GENERAL PUBLIC", "AGPL", "LGPL", "GPL-"];

/// Inputs every Family-21 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct ComplianceFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.compliance.pii_handling"`.
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

/// Build a complete [`Finding`] from a [`ComplianceFindingBlueprint`].
pub(crate) fn build_finding(blueprint: ComplianceFindingBlueprint) -> Finding {
    let ComplianceFindingBlueprint {
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
        .category(Category::Compliance)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-21 finding builder receives all required fields")
}

/// True iff `name` lower-cased contains any [`PII_KEYWORD_TABLE`] entry.
#[must_use]
pub(crate) fn looks_like_pii_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PII_KEYWORD_TABLE.iter().any(|kw| lower.contains(kw))
}

/// True iff `text` lower-cased contains any [`ENCRYPTION_HINTS`] entry.
#[must_use]
pub(crate) fn looks_encrypted(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ENCRYPTION_HINTS.iter().any(|hint| lower.contains(hint))
}

/// True iff `name` lower-cased starts with any [`PRIVILEGED_NAME_PATTERNS`]
/// entry — the function is a privileged administrative operation.
#[must_use]
pub(crate) fn looks_privileged(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PRIVILEGED_NAME_PATTERNS
        .iter()
        .any(|pat| lower.starts_with(pat))
}

/// True iff `path` ends with a license-file pattern from
/// [`LICENSE_FILE_PATTERNS`].
#[must_use]
pub(crate) fn is_license_file(path: &Utf8PathBuf) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    LICENSE_FILE_PATTERNS.iter().any(|pat| {
        lower == *pat
            || lower.starts_with("license-")
            || lower.starts_with("licence-")
            || lower.starts_with("license.")
            || lower.starts_with("licence.")
    })
}
