//! Internal helpers shared across Family-26 (modernization) probes.
//!
//! Sibling-independent of other rule packs; mirrors the small primitive
//! surface used by `cc-rules-bugs` so this pack can ship without coupling
//! to siblings. Canonical callee text comes from
//! [`cc_frontend::query::callee_text`] — never reimplement here.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinModernizePack;

/// Probe-pack identity stamped on every Family-26 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinModernizePack::PACK_ID,
        BuiltinModernizePack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property. Bounded to 256 hops to stay safe
/// against pathological frontends.
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
/// back to start-of-file when the property is missing.
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
/// languages. Mirrors the convention used by `cc-rules-bugs` so probes
/// keep behaviour consistent across packs.
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

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Modernization probes embed concrete
/// detector substrings (`os.path.join`, `format!`, `var `) that would
/// match their own implementation; skip those.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] kept under the
/// pack namespace so call sites remain short. The canonical merge logic
/// lives upstream — every pack scans the same haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
}

/// Python `typing.*` aliases that ruff UP006/UP035 retire in favour of
/// builtin generics on 3.9+. Ordered alphabetically for review hygiene.
pub(crate) const LEGACY_TYPING_ALIASES: &[(&str, &str)] = &[
    ("typing.AbstractSet", "collections.abc.Set"),
    ("typing.AsyncIterable", "collections.abc.AsyncIterable"),
    ("typing.AsyncIterator", "collections.abc.AsyncIterator"),
    ("typing.Awaitable", "collections.abc.Awaitable"),
    ("typing.Callable", "collections.abc.Callable"),
    ("typing.Deque", "collections.deque"),
    ("typing.Dict", "dict"),
    ("typing.FrozenSet", "frozenset"),
    ("typing.Iterable", "collections.abc.Iterable"),
    ("typing.Iterator", "collections.abc.Iterator"),
    ("typing.List", "list"),
    ("typing.Mapping", "collections.abc.Mapping"),
    ("typing.MutableMapping", "collections.abc.MutableMapping"),
    ("typing.MutableSequence", "collections.abc.MutableSequence"),
    ("typing.MutableSet", "collections.abc.MutableSet"),
    ("typing.Sequence", "collections.abc.Sequence"),
    ("typing.Set", "set"),
    ("typing.Tuple", "tuple"),
    ("typing.Type", "type"),
];

/// Python `os.path.join` — the single callee handled by the dedicated
/// `cc.modernize.os_path_join` probe. Kept as a one-element slice so
/// the call site continues using the same iteration shape as the
/// broader [`OS_PATH_PATHLIB_CALLEES`] used by the wider Phase-8
/// `use_pathlib_over_os` probe.
pub(crate) const OS_PATH_CALLEES: &[&str] = &["os.path.join"];

/// Python `os.path.*` callees other than `os.path.join` that prefer
/// their `pathlib.Path` equivalents. Each entry pairs the legacy
/// callee with its modern replacement so the Phase-8
/// `use_pathlib_over_os` probe can show both spellings to the user.
/// Ordered alphabetically for review hygiene.
pub(crate) const OS_PATH_PATHLIB_CALLEES: &[(&str, &str)] = &[
    ("os.path.abspath", "Path(p).resolve()"),
    ("os.path.basename", "Path(p).name"),
    ("os.path.dirname", "Path(p).parent"),
    ("os.path.exists", "Path(p).exists()"),
    ("os.path.getsize", "Path(p).stat().st_size"),
    ("os.path.isdir", "Path(p).is_dir()"),
    ("os.path.isfile", "Path(p).is_file()"),
    ("os.path.splitext", "(Path(p).stem, Path(p).suffix)"),
];

/// Inputs every Family-26 rule supplies when emitting a [`Finding`].
///
/// Mirrors the named-field pattern used by `Tier0FindingBlueprint` /
/// `BugFindingBlueprint`: callers pass `ModernizeFindingBlueprint { … }`
/// and read like English instead of guessing argument order.
#[derive(Debug)]
pub(crate) struct ModernizeFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.modernize.os_path_join"`.
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

/// Build a complete [`Finding`] from a [`ModernizeFindingBlueprint`].
///
/// Modernization findings file under [`Category::Slop`] — the Slop bucket
/// is the canonical home for "valid but superseded" patterns. There is no
/// dedicated `Modernize` category in the closed taxonomy.
pub(crate) fn build_finding(blueprint: ModernizeFindingBlueprint) -> Finding {
    let ModernizeFindingBlueprint {
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
        .category(Category::Slop)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-26 finding builder receives all required fields")
}
