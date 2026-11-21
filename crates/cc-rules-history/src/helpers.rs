//! Internal helpers shared across Family-18 probes.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinHistoryPack;

/// Probe-pack identity stamped on every Family-18 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinHistoryPack::PACK_ID,
        BuiltinHistoryPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// True iff `path` is inside one of the kernel's own rule-pack crates.
///
/// Rules whose detection is text-/AST-pattern-based often match their own
/// implementation when the kernel scans itself (the rule's source spells
/// out the patterns it looks for). Probes that produce noise on their own
/// source consult this predicate to skip the kernel's own pack code.
/// Cross-platform path-separator-agnostic.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let normalised = path.as_str().replace('\\', "/").to_ascii_lowercase();
    normalised.contains("/cc-rules-") || normalised.starts_with("crates/cc-rules-")
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

/// Build a [`Location`] anchored at the node's `range` property,
/// falling back to the start-of-file when the property is missing.
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

/// Aging-marker keywords scanned inside [`NodeKind::Comment`] nodes.
pub(crate) const TODO_KEYWORDS: &[&str] = &["TODO", "FIXME", "XXX", "HACK"];

/// Return the first matching [`TODO_KEYWORDS`] token in `text` or
/// `None` if the text contains no aging marker. Match is case-sensitive
/// (mixed-case `Todo` is intentionally NOT flagged — convention is
/// uppercase).
#[must_use]
pub(crate) fn aging_marker(text: &str) -> Option<&'static str> {
    TODO_KEYWORDS.iter().copied().find(|kw| text.contains(kw))
}

/// Inputs every Family-18 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct HistoryFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.rot.todo_aging"`.
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

/// Build a complete [`Finding`] from a [`HistoryFindingBlueprint`].
pub(crate) fn build_finding(blueprint: HistoryFindingBlueprint) -> Finding {
    let HistoryFindingBlueprint {
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
        .category(Category::Rot)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-18 finding builder receives all required fields")
}
