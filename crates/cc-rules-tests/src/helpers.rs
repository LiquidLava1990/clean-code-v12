//! Internal helpers shared across Family-8 (tests) probes.
//!
//! Re-implements the small set of traversal primitives every Family-8
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates. Shape mirrors `cc-rules-bugs::helpers` —
//! single-source-of-truth for `is_test_file_path` lives here for this
//! crate; the canonical version in `cc-rules-tier0::helpers` is kept in
//! lockstep manually because crates do not depend on each other.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinTestsPack;

/// Probe-pack identity stamped on every Family-8 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTestsPack::PACK_ID,
        BuiltinTestsPack::PACK_SEMVER,
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
/// languages — Python, Rust, Go, TypeScript.
///
/// Heuristic copy of `cc_rules_tier0::helpers::is_test_file_path`. The
/// two implementations are kept in lockstep manually because the rule
/// packs deliberately avoid cross-pack imports.
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

/// True iff `name` looks like a test function — the four supported
/// language conventions:
///
/// - Python: `test_*` (pytest), methods on `TestCase` named `test_*`
/// - Rust: any function carrying a `#[test]` attribute (caller-checked
///   via [`function_has_test_attr`]) or named `test_*`
/// - Go: `func TestXxx(t *testing.T)`
/// - TypeScript / JS: top-level `it(...)` / `test(...)` blocks lifted
///   as named functions; we accept both `test_*` and the lowered names.
#[must_use]
pub(crate) fn looks_like_test_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("test_")
        || lower.ends_with("_test")
        || name.starts_with("Test")
        || lower.starts_with("it ")
        || lower.starts_with("test ")
}

/// True iff the function (or method) node carries a `#[test]` /
/// `@pytest.fixture` / similar test-marker decorator.
///
/// We scan every incoming `AST_PARENT` child whose kind is
/// [`NodeKind::Decorator`] and substring-match the decorator's `name`
/// against a small set of universally-test markers.
#[must_use]
pub(crate) fn function_has_test_attr(batch: &CpgWriteBatch, fn_id: NodeId) -> bool {
    use cc_cpg::EdgeKind;
    use cc_frontend::query::incoming_edges_of_kind;
    for edge in incoming_edges_of_kind(batch, fn_id, EdgeKind::AST_PARENT) {
        let Some(child_kind) = node_kind(batch, edge.from) else {
            continue;
        };
        if child_kind != NodeKind::Decorator {
            continue;
        }
        let Some(name) = string_prop(batch, edge.from, "name") else {
            continue;
        };
        if is_test_decorator(name) {
            return true;
        }
    }
    false
}

fn is_test_decorator(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("test")
        || lower.contains("pytest")
        || lower.contains("hypothesis.given")
        || lower.contains("benchmark")
}

/// Substring needles every Family-8 rule treats as "this Call site is
/// an assertion".
///
/// Substring rather than exact equality so we cover every supported
/// language's assertion vocabulary. New entries belong here, not
/// inside individual probes — single source of truth.
pub(crate) const ASSERT_CALLEES: &[&str] = &[
    // Rust — std + `pretty_assertions` + `claims`. Frontends lift
    // `assert_eq!(…)` as a macro Call whose `callee_ref` is the macro
    // path (`assert_eq`) without the bang, so we register both forms.
    "assert!",
    "assert_eq!",
    "assert_ne!",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert!",
    "debug_assert_eq!",
    "debug_assert_ne!",
    "debug_assert",
    ".unwrap()",
    ".expect(",
    "assert_matches!",
    "assert_matches",
    "assert_ok!",
    "assert_err!",
    "assert_ok",
    "assert_err",
    "panic!",
    "panic",
    "unreachable!",
    "unreachable",
    "unimplemented!",
    "todo!",
    // Python — unittest + pytest
    "assert ",
    "assertEqual",
    "assertNotEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIsNone",
    "assertIsNotNone",
    "assertIn",
    "assertNotIn",
    "assertRaises",
    "pytest.raises",
    "pytest.approx",
    // JS / TS — jest + chai + node
    "expect(",
    ".toBe(",
    ".toEqual(",
    ".toHaveBeenCalled",
    ".toThrow",
    "should.be",
    "should.equal",
    "assert.equal",
    "assert.deepEqual",
    "assert.strictEqual",
    "assert.that",
    // Go — testing + testify
    "t.Errorf",
    "t.Fatalf",
    "t.Fatal(",
    "t.Error(",
    "require.Equal",
    "require.NoError",
    "assert.Equal",
    "assert.NoError",
];

/// Substring needles indicating that a call's *receiver* is itself a
/// mock / stub / spy / fake. Used by `cc.test.tests_the_mock`.
///
/// Case-insensitive — we lower-case the candidate before matching.
pub(crate) const MOCK_NAME_NEEDLES: &[&str] =
    &["mock", "fake", "stub", "spy", "magicmock", "mockito"];

/// Inputs every Family-8 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct TestsFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.test.assertion_free"`.
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

/// Build a complete [`Finding`] from a [`TestsFindingBlueprint`].
pub(crate) fn build_finding(blueprint: TestsFindingBlueprint) -> Finding {
    let TestsFindingBlueprint {
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
        .category(Category::Test)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-8 finding builder receives all required fields")
}
