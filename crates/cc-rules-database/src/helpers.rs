//! Internal helpers shared across Family-10 (database) probes.
//!
//! Re-implements the small set of traversal primitives every Family-10
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinDatabasePack;

/// Probe-pack identity stamped on every Family-10 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinDatabasePack::PACK_ID,
        BuiltinDatabasePack::PACK_SEMVER,
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

/// Build a [`Location`] anchored at the start of `file`. Used by the
/// source-bytes scanners that don't have a node id to point at.
pub(crate) fn location_for_file(file: Utf8PathBuf, line: u32) -> Location {
    let pos = Position::new(line, 1, 0);
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

/// True iff `path` looks like a database migration file. Recognises
/// Django / Alembic / Flyway / Rails-style basenames as well as bare
/// `migrations/*.sql`.
#[must_use]
pub(crate) fn is_migration_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if lower.contains("/migrations/") || lower.starts_with("migrations/") {
        return true;
    }
    let Some(stem) = path.file_stem().map(str::to_ascii_lowercase) else {
        return false;
    };
    stem.ends_with("_migration") || stem.ends_with(".migration")
}

/// Field-name fragments that suggest the column should be relational
/// rather than JSON. Used by `cc.db.json_blob_hellscape`.
pub(crate) const JSON_BLOB_FIELD_PATTERNS: &[&str] =
    &["config_", "settings_", "data_", "metadata_"];

/// Suffix tokens that, combined with a structured prefix, escalate the
/// finding (`config_dict`, `data_blob`, …).
pub(crate) const JSON_BLOB_SUFFIXES: &[&str] = &["_dict", "_blob"];

/// Inputs every Family-10 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct DatabaseFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.db.locking_migration"`.
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

/// Build a complete [`Finding`] from a [`DatabaseFindingBlueprint`].
pub(crate) fn build_finding(blueprint: DatabaseFindingBlueprint) -> Finding {
    let DatabaseFindingBlueprint {
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
        .category(Category::Db)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-10 finding builder receives all required fields")
}
