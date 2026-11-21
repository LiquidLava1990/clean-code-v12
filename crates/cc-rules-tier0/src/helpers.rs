//! Internal helpers shared across Tier-0 rules.
//!
//! Anything that gets used by two or more rule files lives here, so we
//! never duplicate traversal logic. New helpers belong in
//! `cc_frontend::query` when they are universally useful (we already
//! contributed `range_prop`, `int_prop`, `bool_prop`); helpers in this
//! module are Tier-0-specific (e.g. logical-LOC counting).

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, range_prop, string_prop};

use crate::pack::BuiltinTier0Pack;

/// Probe-pack identity stamped on every Tier-0 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTier0Pack::PACK_ID,
        BuiltinTier0Pack::PACK_SEMVER,
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
        if let Some(node) = cc_frontend::query::node_by_id(batch, id) {
            if node.kind == NodeKind::File {
                return string_prop(batch, id, "path").map(Utf8PathBuf::from);
            }
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

/// True iff `path` points at this kernel's own rule-pack source under
/// `crates/cc-rules-*`. Tier-0 probes that scan for needles (verb
/// strings, regex patterns, message keywords) hit themselves on the
/// kernel codebase — same self-host short-circuit Family 18 already
/// uses. Mirrors `cc-rules-history`'s pack-private helper because
/// neither crate exports one.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let normalised = path.as_str().replace('\\', "/").to_ascii_lowercase();
    normalised.contains("/cc-rules-") || normalised.starts_with("crates/cc-rules-")
}

/// True iff `path` looks like a test file across the four supported
/// languages. Heuristic — covers `tests/` directory placement and the
/// canonical naming conventions:
///
/// - Python: `test_*.py`, `*_test.py`, files under `tests/`
/// - Rust: `tests/`, `*_test.rs`, the conventional crate-private `tests.rs`
/// - Go: `*_test.go`
/// - TypeScript: `*.test.ts`, `*.spec.ts`, files under `__tests__/`
///
/// Used by R-DUP (test setup boilerplate is legitimate duplication) and
/// any future rule whose semantics differ inside test files.
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

/// Slice into the source byte range without allocating. Saturates on
/// over-long ranges. Used by every rule that needs the raw body bytes
/// (R-FN-LEN, R-DUP, …).
#[must_use]
pub(crate) fn byte_window(bytes: &[u8], start: u32, end: u32) -> &[u8] {
    let s = (start as usize).min(bytes.len());
    let e = (end as usize).min(bytes.len()).max(s);
    &bytes[s..e]
}

/// Slice the source bytes for a `[start_offset, end_offset)` byte range
/// and return a UTF-8 [`String`]. Invalid UTF-8 yields an empty string —
/// rule snippets are best-effort and never fatal.
#[must_use]
pub(crate) fn snippet_from_bytes(bytes: &[u8], start: u32, end: u32) -> String {
    let s = start as usize;
    let e = (end as usize).min(bytes.len());
    if s >= e {
        return String::new();
    }
    std::str::from_utf8(&bytes[s..e])
        .map(str::to_owned)
        .unwrap_or_default()
}

/// Count logical lines (non-blank, non-comment-only) in `bytes`.
///
/// Comment-only detection is intentionally loose for Phase 1: a line
/// whose first non-whitespace characters match a known prefix counts as
/// a comment. The four supported languages cover Python (`#`),
/// JS/TS/Rust (`//`), and C-style block prefixes (`/*`, `*`).
#[must_use]
pub(crate) fn logical_line_count(bytes: &[u8]) -> u32 {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let mut count: u32 = 0;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_comment_only(trimmed) {
            continue;
        }
        count = count.saturating_add(1);
    }
    count
}

fn is_comment_only(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("\"\"\"")
        || trimmed.starts_with("'''")
}

/// Inputs every Tier-0 rule supplies when emitting a [`Finding`].
///
/// Replaces a 10-positional-argument constructor with one named-field
/// struct: callers pass `Tier0FindingBlueprint { … }` and read like
/// English instead of guessing argument order.
///
/// All fields are required. There are no defaults — Tier-0 findings are
/// dense by design and a missing remediation or snippet is a rule bug,
/// not a runtime degradation.
#[derive(Debug)]
pub(crate) struct Tier0FindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.shape.cyclomatic"`.
    pub rule_id: &'static str,
    /// Top-level category bucket the rule belongs to.
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

/// Build a complete [`Finding`] from a [`Tier0FindingBlueprint`].
///
/// Centralises the boilerplate shared by every rule (probe version,
/// confidence, kernel stamping). Panics are impossible: every required
/// input is supplied by the caller.
pub(crate) fn build_finding(blueprint: Tier0FindingBlueprint) -> Finding {
    let Tier0FindingBlueprint {
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
        .expect("Tier-0 finding builder receives all required fields")
}
