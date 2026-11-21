//! Internal helpers shared across Family-3 (bugs) probes.
//!
//! Re-implements the small set of traversal primitives every Family-3
//! rule needs so the pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-secrets`, and `cc-rules-perf`.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinBugsPack;

/// Probe-pack identity stamped on every Family-3 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinBugsPack::PACK_ID,
        BuiltinBugsPack::PACK_SEMVER,
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
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for their
/// own detector needles skip these to avoid rule-on-rule noise — e.g.
/// `cc.bug.time_bomb` embeds the literal `"datetime.utcnow()"` as its
/// detector pattern, then would flag itself.
///
/// Phase-3 conservative skip — TODO Phase 5: replace with AST-level
/// detection once frontends expose stable expression nodes.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] kept under the
/// pack namespace so existing call sites don't need updating. The
/// canonical merge logic lives upstream — every pack scans the same
/// haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
}

/// Adjust a brace-depth counter for one line. Returns the new depth.
/// Centralises the `{` / `}` counting pattern shared by Phase-9 Go
/// probes that walk function bodies.
#[must_use]
pub(crate) fn apply_braces(depth: i32, line: &str) -> i32 {
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    depth + opens - closes
}

/// True iff `path` ends in `_test.go`. Phase-9 Go probes share this
/// skip-test-file gate.
#[must_use]
pub(crate) fn is_go_test_path(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

/// Walk backwards from `end` over whitespace, then over the trailing
/// `[A-Za-z0-9_]+` identifier in `s`. Returns the identifier slice or
/// `None` when the position is empty / non-identifier.
///
/// Phase-9 Rust probes use this to recover the identifier preceding
/// `: <type>` (binding annotation) or preceding `as <ty>` (cast).
#[must_use]
pub(crate) fn identifier_ending_at(s: &str, end: usize) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut cursor = end.min(bytes.len());
    while cursor > 0 && bytes[cursor - 1] == b' ' {
        cursor -= 1;
    }
    if cursor == 0 {
        return None;
    }
    let mut start = cursor;
    while start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == cursor {
        return None;
    }
    Some(&s[start..cursor])
}

/// Collect line-index `[start, end)` ranges for every `func ...`
/// whose declaration line satisfies `header_pred`.
#[must_use]
pub(crate) fn collect_function_ranges(
    lines: &[&str],
    header_pred: impl Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if start.is_none()
            && trimmed.starts_with("func ")
            && header_pred(line)
            && line.contains('{')
        {
            start = Some(idx);
            depth = apply_braces(0, line);
            continue;
        }
        if let Some(s) = start {
            depth = apply_braces(depth, line);
            if depth <= 0 {
                out.push((s, idx + 1));
                start = None;
                depth = 0;
            }
        }
    }
    out
}

/// Inputs every Family-3 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct BugFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.bug.null_propagation"`.
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

/// Build a complete [`Finding`] from a [`BugFindingBlueprint`].
pub(crate) fn build_finding(blueprint: BugFindingBlueprint) -> Finding {
    let BugFindingBlueprint {
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
        .category(Category::Bug)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-3 finding builder receives all required fields")
}
