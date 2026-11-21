//! Internal helpers shared across slop rules.
//!
//! These mirror the shape of `cc-rules-tier0::helpers` (re-implemented
//! here so this crate does not depend on Tier-0). When two rules use the
//! same helper it lives here; when one rule needs a one-off it stays
//! local. Helpers that would help other packs belong upstream in
//! `cc_frontend::query` instead.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinSlopPack;

/// Probe-pack identity stamped on every slop finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinSlopPack::PACK_ID,
        BuiltinSlopPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the AST_PARENT chain up to the enclosing [`NodeKind::File`] and
/// return the file's `path` property.
///
/// Returns `None` when the chain breaks or the file node lacks a path.
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

/// Look up the enclosing file's `language` property, walking parents.
#[must_use]
pub(crate) fn enclosing_language(batch: &CpgWriteBatch, mut id: NodeId) -> Option<String> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "language").map(str::to_owned);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property, falling
/// back to the start-of-file when the property is missing.
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

/// Inputs every slop rule supplies when emitting a [`Finding`].
///
/// Mirrors `Tier0FindingBlueprint` so callers read top-down without
/// guessing positional argument order. All fields required by design.
#[derive(Debug)]
pub(crate) struct SlopFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.slop.fake_thoughtful_name"`.
    pub rule_id: &'static str,
    /// Top-level category bucket (always [`Category::Slop`] for this pack).
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

/// Build a complete [`Finding`] from a [`SlopFindingBlueprint`].
pub(crate) fn build_finding(blueprint: SlopFindingBlueprint) -> Finding {
    let SlopFindingBlueprint {
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
        .expect("slop finding builder receives all required fields")
}

/// True iff `name` matches the canonical fake-thoughtful suffix set:
/// `_helper` / `_helpers` / `_util` / `_utils` / `_manager` / `_handler`.
///
/// Pure-letter prefix rule: anything before the suffix must be at least
/// one alphanumeric character, so a bare `helper` (no underscore) does
/// NOT count — only suffixed forms.
///
/// Tightening (Phase-2 self-host pass): a multi-segment name only counts
/// when its FIRST segment is itself a vague verb (`get`, `do`, `process`,
/// `handle`, `make`, `run`). This stops the rule firing on descriptive
/// names like `try_has_bare_handler` (the meaningful verb-phrase
/// `try_has_bare` carries the intent, the trailing `handler` is a noun).
#[must_use]
pub(crate) fn is_fake_thoughtful_suffix(name: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "_helper", "_helpers", "_util", "_utils", "_manager", "_handler",
    ];
    let lower = name.to_ascii_lowercase();
    for suffix in SUFFIXES {
        let Some(prefix) = lower.strip_suffix(suffix) else {
            continue;
        };
        if prefix.is_empty() || !prefix.chars().any(char::is_alphanumeric) {
            continue;
        }
        if prefix_is_vague_or_single_segment(prefix) {
            return true;
        }
    }
    false
}

/// True iff `prefix` (the part of the name before the trailing vague
/// suffix) signals a vague identifier:
///
/// - a single-segment prefix is always vague (`user_helper`, `string_util`).
/// - a multi-segment prefix is vague only when its FIRST segment is one
///   of the canonical vague verbs.
fn prefix_is_vague_or_single_segment(prefix: &str) -> bool {
    const VAGUE_FIRST_SEGMENTS: &[&str] = &[
        "get", "do", "process", "handle", "make", "run", "perform", "execute",
    ];
    let trimmed = prefix.trim_end_matches('_');
    if !trimmed.contains('_') {
        return true;
    }
    let Some(first) = trimmed.split('_').next() else {
        return true;
    };
    VAGUE_FIRST_SEGMENTS.contains(&first)
}

/// True iff `path` looks like a test file across the four supported
/// languages. Mirrors `cc-rules-tier0::helpers::is_test_file_path` —
/// re-implemented locally so this crate has no Tier-0 dep.
///
/// Used by name / comment heuristics that legitimately match in test
/// fixtures (a `*_helper` test fn name is intentional, a comment that
/// restates `parses_hello_world` is a documentation choice).
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_thoughtful_recognises_underscore_suffixes() {
        assert!(is_fake_thoughtful_suffix("user_helper"));
        assert!(is_fake_thoughtful_suffix("legacy_manager"));
        assert!(is_fake_thoughtful_suffix("event_handler"));
        assert!(is_fake_thoughtful_suffix("string_utils"));
        assert!(is_fake_thoughtful_suffix("string_util"));
    }

    #[test]
    fn fake_thoughtful_skips_bare_or_unrelated() {
        assert!(!is_fake_thoughtful_suffix("helper"));
        assert!(!is_fake_thoughtful_suffix("compute"));
        assert!(!is_fake_thoughtful_suffix("_helper"));
        assert!(!is_fake_thoughtful_suffix(""));
        // PascalCase concatenation without `_` separator doesn't match
        // the probe pattern (`*_manager`, etc.).
        assert!(!is_fake_thoughtful_suffix("LegacyManager"));
    }

    #[test]
    fn fake_thoughtful_skips_multi_segment_descriptive_names() {
        // Descriptive verb-phrase names with a noun suffix: NOT vague.
        assert!(!is_fake_thoughtful_suffix("try_has_bare_handler"));
        assert!(!is_fake_thoughtful_suffix("compile_request_handler"));
        assert!(!is_fake_thoughtful_suffix("parse_token_helper"));
    }

    #[test]
    fn fake_thoughtful_flags_multi_segment_with_vague_verb() {
        // Multi-segment, first segment is a vague verb: VAGUE.
        assert!(is_fake_thoughtful_suffix("get_user_helper"));
        assert!(is_fake_thoughtful_suffix("process_event_handler"));
        assert!(is_fake_thoughtful_suffix("do_thing_util"));
        assert!(is_fake_thoughtful_suffix("handle_request_manager"));
    }

    #[test]
    fn is_test_file_path_recognises_canonical_layouts() {
        assert!(is_test_file_path(&Utf8PathBuf::from("src/tests.rs")));
        assert!(is_test_file_path(&Utf8PathBuf::from(
            "crates/foo/src/tests.rs"
        )));
        assert!(is_test_file_path(&Utf8PathBuf::from(
            "crates/foo/tests/frontend.rs"
        )));
        assert!(is_test_file_path(&Utf8PathBuf::from(
            "tests/integration.rs"
        )));
        assert!(is_test_file_path(&Utf8PathBuf::from("foo_test.go")));
        assert!(is_test_file_path(&Utf8PathBuf::from("test_widget.py")));
        assert!(!is_test_file_path(&Utf8PathBuf::from(
            "crates/foo/src/lib.rs"
        )));
    }
}
