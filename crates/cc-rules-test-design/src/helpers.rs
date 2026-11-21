//! Internal helpers shared across Family-28 (test design) probes.
//!
//! Re-implements the small set of traversal primitives every Family-28
//! rule needs so the pack stays sibling-independent of the other
//! `cc-rules-*` crates. `is_test_file_path` is replicated here (kept in
//! lockstep manually with `cc_rules_tier0::helpers::is_test_file_path`)
//! because rule packs deliberately avoid cross-pack imports.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinTestDesignPack;

/// Probe-pack identity stamped on every Family-28 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTestDesignPack::PACK_ID,
        BuiltinTestDesignPack::PACK_SEMVER,
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

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for
/// their own detector needles skip these to avoid rule-on-rule noise.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// True iff `path` looks like a test file across the four supported
/// languages — Python, Rust, Go, TypeScript.
///
/// Heuristic copy of `cc_rules_tier0::helpers::is_test_file_path`, kept
/// in lockstep manually because rule packs avoid cross-pack imports.
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

/// True iff `name` looks like a test function across the four supported
/// language conventions.
#[must_use]
pub(crate) fn looks_like_test_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("test_")
        || lower.ends_with("_test")
        || name.starts_with("Test")
        || lower.starts_with("it ")
        || lower.starts_with("test ")
}

/// True iff the function (or method) carries a `#[test]` /
/// `@pytest.fixture` / similar test marker. Mirrors the helper in
/// [`cc_rules_tests`].
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
        if decorator_text_matches(batch, edge.from, is_test_decorator_text) {
            return true;
        }
    }
    false
}

fn is_test_decorator_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("test")
        || lower.contains("pytest")
        || lower.contains("hypothesis.given")
        || lower.contains("benchmark")
}

/// Read decorator text from any of the slots a frontend may populate
/// (`name`, `expression`, `qualified`) and run `predicate` against it.
#[must_use]
pub(crate) fn decorator_text_matches(
    batch: &CpgWriteBatch,
    decorator_id: NodeId,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    for key in ["name", "expression", "qualified"] {
        if let Some(value) = string_prop(batch, decorator_id, key) {
            if predicate(value) {
                return true;
            }
        }
    }
    false
}

/// True iff every link in `id`'s ancestor chain eventually reaches
/// `target` within 256 hops.
#[must_use]
pub(crate) fn is_descendant_of(batch: &CpgWriteBatch, id: NodeId, target: NodeId) -> bool {
    let mut cursor = id;
    for _ in 0..256_u16 {
        let Some(parent) = ast_parent(batch, cursor) else {
            return false;
        };
        if parent == target {
            return true;
        }
        cursor = parent;
    }
    false
}

/// True iff `name` is a recognised test-function name AND the enclosing
/// file looks like a test file. Used by every rule that needs to gate
/// on "is this an actual test function?". Returns `None` when the file
/// path is unknown; the caller treats `None` as "not a test".
#[must_use]
pub(crate) fn is_test_function(
    batch: &CpgWriteBatch,
    fn_id: NodeId,
) -> Option<(Utf8PathBuf, String)> {
    let path = enclosing_file_path(batch, fn_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let name = string_prop(batch, fn_id, "name")?;
    if !looks_like_test_name(name) && !function_has_test_attr(batch, fn_id) {
        return None;
    }
    Some((path, name.to_owned()))
}

/// Substring needles every Family-28 rule treats as "this Call site is
/// an assertion". Substring rather than exact equality so we cover
/// every supported language's assertion vocabulary.
pub(crate) const ASSERT_CALLEES: &[&str] = &[
    // Rust
    "assert!",
    "assert_eq!",
    "assert_ne!",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert!",
    "debug_assert_eq!",
    "debug_assert_ne!",
    ".unwrap()",
    ".expect(",
    "assert_matches!",
    "assert_matches",
    "panic!",
    "panic",
    // Python
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
    // JS / TS
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
    // Go
    "t.Errorf",
    "t.Fatalf",
    "t.Fatal(",
    "t.Error(",
    "require.Equal",
    "require.NoError",
    "assert.Equal",
    "assert.NoError",
];

/// Substring needles indicating a call source is non-deterministic
/// (time / random / uuid / clock). Used by `cc.test.flaky_iteration`.
pub(crate) const NON_DETERMINISTIC_CALLEES: &[&str] = &[
    // time
    "time.now",
    "time.time",
    "Instant::now",
    "Date.now",
    "SystemTime::now",
    "Utc::now",
    "Local::now",
    "datetime.now",
    "datetime.utcnow",
    "performance.now",
    // random
    "random.random",
    "random.randint",
    "random.choice",
    "rand::",
    "Math.random",
    "rand.Intn",
    "rand.Float",
    "secrets.token",
    // uuid
    "uuid.uuid4",
    "uuid.uuid1",
    "Uuid::new_v4",
    "crypto.randomUUID",
];

/// Inputs every Family-28 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct TestDesignFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.test.unconditional_assert_true"`.
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

/// Build a complete [`Finding`] from a [`TestDesignFindingBlueprint`].
pub(crate) fn build_finding(blueprint: TestDesignFindingBlueprint) -> Finding {
    let TestDesignFindingBlueprint {
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
        .expect("Family-28 finding builder receives all required fields")
}
