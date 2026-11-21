//! Internal helpers shared across Family-2 perf probes.
//!
//! All Phase-1 frontends store the callee identity on a [`NodeKind::Call`]
//! node as either the `name` string prop (Python / Rust / Go method names)
//! or the `signature` string prop (TS qualified callee). Probes treat the
//! pair as a single search target via [`callee_text`].

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinPerfPack;

/// Probe-pack identity stamped on every Family-2 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinPerfPack::PACK_ID,
        BuiltinPerfPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property.
///
/// Bounded to 256 hops — beyond that the chain is treated as broken to
/// avoid pathological loops. Returns `None` when the chain breaks or no
/// file path is recorded.
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

/// Walk the `AST_PARENT` chain looking for a node whose kind matches
/// `target`. Stops at [`NodeKind::Function`] / [`NodeKind::Method`] /
/// [`NodeKind::File`] — perf probes never want to escape the enclosing
/// function body when searching upward.
#[must_use]
pub(crate) fn find_ancestor_kind(
    batch: &CpgWriteBatch,
    mut id: NodeId,
    target: NodeKind,
) -> Option<NodeId> {
    for _ in 0..256_u16 {
        let parent = ast_parent(batch, id)?;
        let kind = node_kind(batch, parent)?;
        if kind == target {
            return Some(parent);
        }
        if matches!(kind, NodeKind::Function | NodeKind::Method | NodeKind::File) {
            return None;
        }
        id = parent;
    }
    None
}

/// Walk the `AST_PARENT` chain looking for the enclosing
/// [`NodeKind::Function`] / [`NodeKind::Method`] node. Returns `None`
/// when the symbol is module-level.
#[must_use]
pub(crate) fn enclosing_function(batch: &CpgWriteBatch, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        let parent = ast_parent(batch, id)?;
        if matches!(
            node_kind(batch, parent),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            return Some(parent);
        }
        id = parent;
    }
    None
}

/// True iff `id` lies inside any descendant body of a [`NodeKind::Loop`]
/// without first crossing a function boundary.
#[must_use]
pub(crate) fn is_inside_loop(batch: &CpgWriteBatch, id: NodeId) -> bool {
    find_ancestor_kind(batch, id, NodeKind::Loop).is_some()
}

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] — every pack
/// uses the same canonical merge logic so substring needles see a
/// uniform haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
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

/// True iff `path` ends in `_test.go` (the only canonical Go test
/// convention). Used by Phase-9 Go probes to skip test files.
#[must_use]
pub(crate) fn is_go_test_path(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

/// True iff `path` looks like a Python test source file
/// (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`). Phase-12
/// Python perf probes share this skip.
#[must_use]
pub(crate) fn is_test_file_path_py(path: &Utf8PathBuf) -> bool {
    if path_has_tests_segment(path) {
        return true;
    }
    let Some(stem) = path.file_stem() else {
        return false;
    };
    let stem_lower = stem.to_ascii_lowercase();
    stem_lower == "conftest" || stem_test_naming_matches(&stem_lower)
}

fn path_has_tests_segment(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/tests/")
        || s.contains("/test/")
        || s.starts_with("tests/")
        || s.starts_with("test/")
}

fn stem_test_naming_matches(stem_lower: &str) -> bool {
    stem_lower.starts_with("test_") || stem_lower.ends_with("_test")
}

/// True iff `path` is a JavaScript / TypeScript source file by extension.
/// Used by Phase-12 cross-language perf probes (e.g. recursion-concat).
#[must_use]
pub(crate) fn is_js_or_ts_path(path: &Utf8PathBuf) -> bool {
    matches!(
        path.extension(),
        Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs")
    )
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for
/// their own detector needles skip these to avoid rule-on-rule noise.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// True iff `path` looks like a Rust test source file
/// (`tests/`, `*_test.rs`, `tests.rs`). Phase-9 Rust probes share
/// this skip.
#[must_use]
pub(crate) fn is_rust_test_path(path: &Utf8PathBuf) -> bool {
    if path_has_tests_segment(path) {
        return true;
    }
    let Some(stem) = path.file_stem() else {
        return false;
    };
    let stem_lower = stem.to_ascii_lowercase();
    stem_lower == "tests" || stem_test_naming_matches(&stem_lower)
}

/// Walk backwards from `end` over whitespace, then over the trailing
/// `[A-Za-z0-9_]+` identifier in `s`. Returns the identifier slice or
/// `None` when the position is empty / non-identifier.
///
/// Phase-9 Rust probes use this to recover the identifier preceding
/// `: <type>` (binding annotation) or preceding `.iter()` / `as <ty>`
/// (method-chain LHS / cast).
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

/// Adjust a brace-depth counter for one line. Centralises the `{` /
/// `}` counting pattern shared by Phase-9 Go probes.
#[must_use]
pub(crate) fn apply_braces(depth: i32, line: &str) -> i32 {
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    depth + opens - closes
}

/// Find the line index at which the brace block opened on `start_idx`
/// closes. Used by Phase-9 Go probes that need to scope follow-up
/// scanning to a single function / loop body.
#[must_use]
pub(crate) fn find_matching_brace_end(lines: &[&str], start_idx: usize) -> usize {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    for (idx, line) in lines.iter().enumerate().skip(start_idx) {
        depth = apply_braces(depth, line);
        if line.contains('{') {
            seen_open = true;
        }
        if seen_open && depth <= 0 {
            return idx + 1;
        }
    }
    lines.len()
}

/// Collect line-index `[start, end)` ranges for every `func ...` whose
/// declaration line satisfies `header_pred`.
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

/// Inputs every perf probe supplies when emitting a [`Finding`].
///
/// Mirrors the named-field constructor pattern from `cc-rules-tier0`. All
/// fields are required — a missing remediation or snippet is a probe bug,
/// not a runtime degradation.
#[derive(Debug)]
pub(crate) struct PerfFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.perf.n_plus_one_orm"`.
    pub rule_id: &'static str,
    /// Severity stamped on the finding.
    pub severity: Severity,
    /// Calibrated confidence the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the slow path manifests.
    pub location: Location,
    /// One-line headline shown first in any sink.
    pub headline: String,
    /// Multi-sentence "why this is slow" explanation.
    pub explanation: String,
    /// Concrete remediation guidance the user can act on.
    pub remediation: Remediation,
    /// Source-code snippet anchoring the finding (may be empty).
    pub snippet: String,
    /// Blocking-debt weight for score impact.
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`PerfFindingBlueprint`].
///
/// Centralises probe-version stamping, confidence gating, and cost
/// claims so individual probe files stay focused on the detection logic.
pub(crate) fn build_finding(blueprint: PerfFindingBlueprint) -> Finding {
    let PerfFindingBlueprint {
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
        .category(Category::Perf)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("perf finding builder receives all required fields")
}
