//! Internal helpers shared across Family-9 (API + schema drift) probes.
//!
//! Re-implements the small set of traversal primitives every Family-9
//! rule needs so the pack stays sibling-independent of the other
//! Phase-4 packs.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinApiPack;

/// Function-name suffixes that mark a public HTTP / RPC handler across
/// the four supported languages. Matched case-insensitively against the
/// `name` property of [`NodeKind::Function`] / [`NodeKind::Method`].
pub(crate) const HANDLER_NAME_PATTERNS: &[&str] = &[
    "_handler",
    "_endpoint",
    "_view",
    "_controller",
    "Handler",
    "Endpoint",
    "View",
    "Controller",
];

/// Return-type strings that mark a public HTTP / RPC handler regardless
/// of name. Matched case-insensitively as substrings of the `return_type`
/// property; this catches Axum / Actix / Django / Flask / `FastAPI` /
/// Express / Gin / Echo idioms uniformly.
pub(crate) const RESPONSE_TYPE_PATTERNS: &[&str] = &[
    "Response",
    "JsonResponse",
    "IntoResponse",
    "actix_web::HttpResponse",
    "HttpResponse",
    "ResponseEntity",
    "Result<Response",
    "Result<JsonResponse",
];

/// Probe-pack identity stamped on every Family-9 finding.
#[must_use]
pub(crate) const fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinApiPack::PACK_ID,
        BuiltinApiPack::PACK_SEMVER,
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
    matches!(stem_lower, "tests" | "test")
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

/// True iff the function `name` or `return_type` matches one of the
/// canonical handler markers. Either signal is sufficient — Axum
/// handlers in Rust often carry a generic name (`get_user`) but a
/// canonical [`RESPONSE_TYPE_PATTERNS`] return type, while Django /
/// Flask handlers go the other way (canonical name, generic dict
/// return).
#[must_use]
pub(crate) fn looks_like_handler(name: Option<&str>, return_type: Option<&str>) -> bool {
    let by_name = name.is_some_and(|n| HANDLER_NAME_PATTERNS.iter().any(|p| matches_pattern(n, p)));
    let by_return =
        return_type.is_some_and(|r| RESPONSE_TYPE_PATTERNS.iter().any(|p| r.contains(p)));
    by_name || by_return
}

/// Case-insensitive substring match — the handler patterns are short
/// enough that allocating a single owned lower-case copy of `haystack`
/// per call is fine for Phase-4 throughput.
fn matches_pattern(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Inputs every Family-9 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct ApiFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.api.response_shape_drift"`.
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

/// Build a complete [`Finding`] from an [`ApiFindingBlueprint`].
pub(crate) fn build_finding(blueprint: ApiFindingBlueprint) -> Finding {
    let ApiFindingBlueprint {
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
        .category(Category::Api)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-9 finding builder receives all required fields")
}
