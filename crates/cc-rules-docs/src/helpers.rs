//! Internal helpers shared across Family-16 probes.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{
    ast_children, ast_parent, node_kind, nodes_of_kind, range_prop, string_prop,
};

use crate::pack::BuiltinDocsPack;

/// Probe-pack identity stamped on every Family-16 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinDocsPack::PACK_ID,
        BuiltinDocsPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// True iff `path` looks like a test file across the four supported
/// languages. Public surface in test files is consumed by the test
/// runner / fixture harness, not by application callers — undocumented
/// `pub` test helpers are not a docs-coverage gap.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let lower = path
        .as_str()
        .replace(chr_backslash(), "/")
        .to_ascii_lowercase();
    if lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
    {
        return true;
    }
    let Some(stem) = path.file_stem() else {
        return false;
    };
    let stem_lower = stem.to_ascii_lowercase();
    stem_lower == "tests"
        || stem_lower == "test"
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

const fn chr_backslash() -> char {
    '\\'
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Phase-10 docstring probes scan source
/// text on Python files; rule-pack source uses `.rs` so the probes are
/// safe regardless, but mirroring the sibling-pack convention keeps the
/// detector noise floor consistent across packs.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
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

/// Patterns that introduce a parameter name inside a docstring across
/// the three conventions Phase-5 supports. Order matters only for
/// readability — the first match wins per docstring line.
pub(crate) const DOCSTRING_PARAM_PATTERNS: &[&str] = &[
    ":param ",   // Python (Sphinx)
    "@param ",   // JSDoc / Java
    "* @param ", // JSDoc star-prefixed
];

/// Comment-language prefixes recognised when scanning preceding text
/// for a doc-comment. Matched against `trim_start`-ed text so leading
/// whitespace is ignored.
pub(crate) const COMMENT_LANG_PREFIXES: &[&str] = &[
    "///",    // Rust outer doc
    "//!",    // Rust inner doc
    "/**",    // C-style block doc (JSDoc, Doxygen, JavaDoc)
    "\"\"\"", // Python triple-double
    "'''",    // Python triple-single
    "#",      // Python / shell-style line comment
    "//",     // C-style line comment
];

/// Return every [`NodeKind::Parameter`] node whose `AST_PARENT` is
/// `function_id`, ordered by their `position` integer property when
/// available. Parameters with `is_self == true` are excluded — `self`
/// / `cls` never appear in Python docstrings.
#[must_use]
pub(crate) fn function_parameter_names(batch: &CpgWriteBatch, function_id: NodeId) -> Vec<String> {
    let mut entries: Vec<(u64, String)> = ast_children(batch, function_id)
        .filter(|child| node_kind(batch, *child) == Some(NodeKind::Parameter))
        .filter(|child| !cc_frontend::query::bool_prop(batch, *child, "is_self").unwrap_or(false))
        .filter_map(|child| {
            let name = string_prop(batch, child, "name")?.to_owned();
            let pos = position_of(batch, child);
            Some((pos, name))
        })
        .collect();
    entries.sort_by_key(|(pos, _)| *pos);
    entries.into_iter().map(|(_, name)| name).collect()
}

/// Read the `position` property as `u64`, defaulting to `u64::MAX` so
/// position-less parameters sort to the end without disturbing relative
/// order of indexed entries.
fn position_of(batch: &CpgWriteBatch, id: NodeId) -> u64 {
    cc_frontend::query::int_prop(batch, id, "position")
        .map(|i| u64::try_from(i).unwrap_or(u64::MAX))
        .or_else(
            || match cc_frontend::query::node_by_id(batch, id)?.prop("position")? {
                cc_cpg::Value::Uint(u) => Some(*u),
                _ => None,
            },
        )
        .unwrap_or(u64::MAX)
}

/// Find the [`NodeKind::Comment`] whose end-line falls within
/// `max_line_gap` lines of `target_id`'s start line. Returns the first
/// match in iteration order — sufficient because the kernel emits
/// comments at most once per source range.
#[must_use]
pub(crate) fn preceding_comment(
    batch: &CpgWriteBatch,
    target_id: NodeId,
    max_line_gap: u32,
) -> Option<NodeId> {
    let target_range = range_prop(batch, target_id, "range")?;
    let target_start_line = target_range.start.line;
    nodes_of_kind(batch, NodeKind::Comment)
        .filter_map(|comment| {
            let comment_range = range_prop(batch, comment.id, "range")?;
            let gap = target_start_line.checked_sub(comment_range.end.line)?;
            (gap <= max_line_gap).then_some(comment.id)
        })
        .next()
}

/// True iff `id` is a public-visibility function — `is_pub` /
/// `is_export` flags or `visibility == "public"`. Centralised so every
/// docs probe sees the same definition.
#[must_use]
pub(crate) fn is_public_function(batch: &CpgWriteBatch, id: NodeId) -> bool {
    if cc_frontend::query::bool_prop(batch, id, "is_pub").unwrap_or(false) {
        return true;
    }
    if cc_frontend::query::bool_prop(batch, id, "is_export").unwrap_or(false) {
        return true;
    }
    matches!(string_prop(batch, id, "visibility"), Some("public"))
}

/// Inputs every Family-16 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct DocsFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.docs.docstring_coverage"`.
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

/// Build a complete [`Finding`] from a [`DocsFindingBlueprint`].
pub(crate) fn build_finding(blueprint: DocsFindingBlueprint) -> Finding {
    let DocsFindingBlueprint {
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
        .category(Category::Docs)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-16 finding builder receives all required fields")
}
