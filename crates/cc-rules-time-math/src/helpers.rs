//! Internal helpers shared across Family-14 probes.
//!
//! Mirrors the Family-19 helper layout: re-implements the few CPG
//! utilities we need rather than depending on a sibling rule crate.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, range_prop, string_prop};

use crate::pack::BuiltinTimeMathPack;

/// Probe-pack identity stamped on every Family-14 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTimeMathPack::PACK_ID,
        BuiltinTimeMathPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the AST_PARENT chain up to the enclosing [`NodeKind::File`] and
/// return the file's `path` property.
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

/// Inputs every Family-14 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct TimeMathFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.math.naive_datetime"`.
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

/// Build a complete [`Finding`] from a [`TimeMathFindingBlueprint`].
pub(crate) fn build_finding(blueprint: TimeMathFindingBlueprint) -> Finding {
    let TimeMathFindingBlueprint {
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
        .expect("Family-14 finding builder receives all required fields")
}

/// Suffix table flagging variable names whose binding to a float type
/// is overwhelmingly indicative of a money / ratio / measurement bug.
///
/// Used by [`crate::money_in_float`] (binding-type heuristic) and by
/// [`crate::float_equality`] (variable-name fallback).
pub(crate) const MONEY_NAME_SUFFIXES: &[&str] = &[
    "_amount",
    "_price",
    "_cost",
    "_balance",
    "_total",
    "_cents",
    "_dollars",
    "_fee",
    "_fees",
    "_subtotal",
    "_tax",
    "_charge",
    "_payment",
];

/// Suffix table flagging variable names whose float-equality compare is
/// almost always wrong (ratios, rates, percentages, speeds — all
/// measured + accumulate FP error).
pub(crate) const RATIO_NAME_SUFFIXES: &[&str] = &[
    "_ratio",
    "_rate",
    "_pct",
    "_percent",
    "_percentage",
    "_speed",
    "_velocity",
    "_factor",
    "_score",
];

/// Prefix table flagging currency-style identifiers whose binding to
/// `float` should be a fixed-point or `Decimal` instead.
pub(crate) const MONEY_NAME_PREFIXES: &[&str] = &["currency_", "money_", "price_", "amount_"];

/// True iff `name` matches a money-style identifier pattern.
#[must_use]
pub(crate) fn is_money_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if MONEY_NAME_SUFFIXES.iter().any(|suf| lower.ends_with(suf)) {
        return true;
    }
    MONEY_NAME_PREFIXES.iter().any(|pre| lower.starts_with(pre))
}

/// True iff `name` matches a ratio / rate / percentage identifier
/// pattern — the float-equality fallback heuristic.
#[must_use]
pub(crate) fn is_ratio_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    RATIO_NAME_SUFFIXES.iter().any(|suf| lower.ends_with(suf))
}

/// True iff `type_name` looks like a floating-point binding across the
/// four supported languages: Python (`float`), Rust (`f32`/`f64`),
/// JS/TS (`number`), Go (`float32`/`float64`).
#[must_use]
pub(crate) fn is_float_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "float" | "f32" | "f64" | "number" | "Number" | "float32" | "float64" | "double"
    )
}

/// True iff `s` contains a decimal numeral with a `.` (e.g. `9.99`).
///
/// Shared by [`crate::float_equality`] (two-literal heuristic) and
/// [`crate::money_in_float`] (rhs literal heuristic). Implementation
/// is byte-walker form so nesting stays <= 3.
#[must_use]
pub(crate) fn contains_float_literal(s: &str) -> bool {
    scan_decimal_count(s) >= 1
}

/// Count decimal numerals on `s` that include a `.` and span at least
/// 3 bytes (e.g. `9.9`, `0.1`, `99.99`). Pure byte walker.
#[must_use]
pub(crate) fn scan_decimal_count(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut found = 0_usize;
    let mut i = 0;
    while i < bytes.len() {
        let (len, has_dot) = scan_decimal(bytes, i);
        if has_dot && len >= 3 {
            found = found.saturating_add(1);
        }
        i = if len == 0 { i + 1 } else { i + len };
    }
    found
}

/// One decimal-numeral scan starting at `start`. Returns `(length,
/// has_dot)`. Length zero when `start` is not a digit.
fn scan_decimal(bytes: &[u8], start: usize) -> (usize, bool) {
    if start >= bytes.len() || !bytes[start].is_ascii_digit() {
        return (0, false);
    }
    let mut j = start;
    let mut has_dot = false;
    while j < bytes.len() {
        let b = bytes[j];
        if b.is_ascii_digit() {
            j += 1;
        } else if b == b'.' && !has_dot {
            has_dot = true;
            j += 1;
        } else {
            break;
        }
    }
    (j - start, has_dot)
}
