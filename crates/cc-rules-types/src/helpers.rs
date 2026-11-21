//! Internal helpers shared across Family-22 (types) probes.
//!
//! Re-implements the small set of traversal primitives every Family-22
//! rule needs so the pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-bugs`, etc.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinTypesPack;

/// Implicit-any markers, one per supported language.
///
/// Each entry pairs a language tag (matched against the enclosing
/// `File.language` property) with the canonical surface tokens that
/// represent "no real type". Frontends store the annotation text on
/// the `Parameter.type` / `Function.return_type` props verbatim, so
/// equality against this table is the right level of strictness for
/// Phase 3 — false positives on cosmetic whitespace are caught by
/// trimming before lookup.
pub(crate) const IMPLICIT_ANY_TABLE: &[(&str, &[&str])] = &[
    ("python", &["Any", "typing.Any"]),
    ("py", &["Any", "typing.Any"]),
    ("typescript", &["any"]),
    ("ts", &["any"]),
    ("javascript", &["any"]),
    ("js", &["any"]),
    ("go", &["interface{}", "any"]),
    (
        "rust",
        &["&dyn Any", "&mut dyn Any", "Box<dyn Any>", "dyn Any"],
    ),
    (
        "rs",
        &["&dyn Any", "&mut dyn Any", "Box<dyn Any>", "dyn Any"],
    ),
];

/// Type-checker silencing markers and their language tags.
///
/// The detector walks `Comment` nodes and matches their text against
/// the marker prefixes in this table. The tail of the comment (after
/// the marker) is then inspected for a justification clause; an empty
/// tail means the silencing is unjustified.
pub(crate) const IGNORE_MARKERS: &[(&str, &str)] = &[
    ("# type: ignore", "python"),
    ("# pyright: ignore", "python"),
    ("# noqa", "python"),
    ("// @ts-ignore", "typescript"),
    ("// @ts-expect-error", "typescript"),
    ("// nolint", "go"),
    ("//nolint", "go"),
    ("#[allow(", "rust"),
];

/// Probe-pack identity stamped on every Family-22 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTypesPack::PACK_ID,
        BuiltinTypesPack::PACK_SEMVER,
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

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `language` string property.
#[must_use]
pub(crate) fn enclosing_file_language(batch: &CpgWriteBatch, mut id: NodeId) -> Option<String> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "language").map(str::to_owned);
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

/// True iff the trimmed annotation matches an implicit-any marker for
/// the given language. Unknown languages return `false` (silent skip).
#[must_use]
pub(crate) fn is_implicit_any(annotation: &str, language: &str) -> bool {
    let trimmed = annotation.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lang_lower = language.to_ascii_lowercase();
    for (tag, markers) in IMPLICIT_ANY_TABLE {
        if *tag == lang_lower && markers.iter().any(|m| *m == trimmed) {
            return true;
        }
    }
    false
}

/// True iff `path` looks like a test file. Mirrors the Tier-0 helper of
/// the same name; duplicated here so the Family-22 pack stays
/// sibling-independent.
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

/// True iff `path` is a source file inside a rule-pack crate. Probes
/// whose detector keys are spelt out in their own source code skip
/// these to avoid self-detection noise.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let normalised = path.as_str().replace('\\', "/").to_ascii_lowercase();
    normalised.contains("/cc-rules-") || normalised.starts_with("crates/cc-rules-")
}

/// Inputs every Family-22 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct TypesFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.type.implicit_any"`.
    pub rule_id: &'static str,
    /// Category bucket; defaults are `Type` for the family but probe 6
    /// (`cc.bug.lock_held_across_await`) crosses the boundary into
    /// concurrency-flavoured bug detection and ships as `Bug`.
    pub category: Category,
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

/// Build a complete [`Finding`] from a [`TypesFindingBlueprint`].
pub(crate) fn build_finding(blueprint: TypesFindingBlueprint) -> Finding {
    let TypesFindingBlueprint {
        rule_id,
        category,
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
        .category(category)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-22 finding builder receives all required fields")
}

/// Read the full source text of `path` from the rule context, returning
/// `None` when the file is empty or invalid UTF-8. Used by probes that
/// need raw text (e.g. exhaustruct's struct-literal parsing).
#[must_use]
pub(crate) fn file_source_text<'b>(
    ctx: &cc_rules::RuleContext<'b>,
    path: &Utf8PathBuf,
) -> Option<&'b [u8]> {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

/// Slice `bytes` at the half-open `[start, end)` byte range and decode
/// as UTF-8, returning `None` on bad bounds or invalid UTF-8.
#[must_use]
pub(crate) fn byte_slice_str<'b>(bytes: &'b [u8], start: u32, end: u32) -> Option<&'b str> {
    let s = (start as usize).min(bytes.len());
    let e = (end as usize).min(bytes.len()).max(s);
    std::str::from_utf8(&bytes[s..e]).ok()
}
