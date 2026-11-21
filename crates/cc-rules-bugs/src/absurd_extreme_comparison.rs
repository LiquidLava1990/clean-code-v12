//! `cc.bug.absurd_extreme_comparison` — comparison whose result is
//! statically determined because the casted operand cannot reach the
//! literal on the other side.
//!
//! Canonical bug:
//! ```text
//! let n: u32 = 0;
//! if (n as u8) > 256 { /* always false */ }
//! if (k as i8) > 127 { /* always false */ }
//! if (k as i8) >= -128 { /* always true */ }
//! ```
//! The comparison is dead — it tells the reader the wrong contract and
//! often hides a real bound check the author meant to write.
//!
//! OSS source: clippy `absurd_extreme_comparisons`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files line by line for
//! `as <int_ty> <op> <literal>` patterns where the literal is at or
//! beyond the cast type's representable range. Skip test files and
//! rule-pack source.
//!
//! Confidence 0.95 — the heuristic only fires on literals with a
//! resolved integer cast type, so false positives require deliberately
//! pathological code (e.g. transmute games).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-ABSURD-EXTREME-COMPARISON.
#[derive(Debug, Default, Clone, Copy)]
pub struct AbsurdExtremeComparisonRule;

/// (type-name, signed-min, max) range tuple. The `min` is `None` for
/// unsigned types (`0` is the implicit lower bound).
struct IntRange {
    name: &'static str,
    min: Option<i128>,
    max: i128,
}

const INT_RANGES: &[IntRange] = &[
    IntRange {
        name: "u8",
        min: None,
        max: 255,
    },
    IntRange {
        name: "u16",
        min: None,
        max: 65_535,
    },
    IntRange {
        name: "u32",
        min: None,
        max: 4_294_967_295,
    },
    IntRange {
        name: "i8",
        min: Some(-128),
        max: 127,
    },
    IntRange {
        name: "i16",
        min: Some(-32_768),
        max: 32_767,
    },
    IntRange {
        name: "i32",
        min: Some(-2_147_483_648),
        max: 2_147_483_647,
    },
];

impl Rule for AbsurdExtremeComparisonRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.absurd_extreme_comparison"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "comparison whose result is statically determined by the cast type"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        for range in INT_RANGES {
            if let Some(snippet) = detect_absurd(line, range) {
                out.push(emit(path.clone(), idx + 1, range.name, &snippet));
                break;
            }
        }
    }
}

/// Search for `as <int_ty>` followed within ~32 chars by a comparison
/// against an integer literal that cannot ever be reached.
fn detect_absurd(line: &str, range: &IntRange) -> Option<String> {
    let needle = format!("as {}", range.name);
    let cast_idx = line.find(&needle)?;
    let after = &line[cast_idx + needle.len()..];
    let (op, lit) = next_comparison(after)?;
    if !op_is_extreme(op, lit, range) {
        return None;
    }
    Some(line.trim().chars().take(180).collect())
}

/// Return `(op, literal_value)` for the next comparison in `tail`.
/// Operators recognised: `>`, `>=`, `<`, `<=`, `==`, `!=`.
fn next_comparison(tail: &str) -> Option<(&'static str, i128)> {
    let bytes = tail.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        let (op, op_len) = match (bytes[i], bytes.get(i + 1).copied()) {
            (b'>', Some(b'=')) => (">=", 2),
            (b'<', Some(b'=')) => ("<=", 2),
            (b'=', Some(b'=')) => ("==", 2),
            (b'!', Some(b'=')) => ("!=", 2),
            (b'>', _) => (">", 1),
            (b'<', _) => ("<", 1),
            _ => {
                i += 1;
                continue;
            }
        };
        let after = &tail[i + op_len..];
        let lit = parse_int_literal(after)?;
        return Some((op, lit));
    }
    None
}

fn parse_int_literal(after: &str) -> Option<i128> {
    let trimmed = after.trim_start();
    let (sign, rest) = if let Some(rest) = trimmed.strip_prefix('-') {
        (-1_i128, rest.trim_start())
    } else {
        (1_i128, trimmed)
    };
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let digits: String = rest[..end].chars().filter(|c| *c != '_').collect();
    let value = digits.parse::<i128>().ok()?;
    Some(sign * value)
}

/// True iff `op lit` against `range` is statically true or statically
/// false because `lit` lies outside the range.
fn op_is_extreme(op: &str, lit: i128, range: &IntRange) -> bool {
    let max = range.max;
    let min = range.min.unwrap_or(0);
    match op {
        ">" | ">=" => lit >= max,
        "<" | "<=" => lit <= min,
        "==" | "!=" => lit > max || lit < min,
        _ => false,
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, ty: &str, snippet: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.absurd_extreme_comparison",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("comparison against `{ty}` extremum is statically determined",),
        explanation: format!(
            "The cast to `{ty}` bounds the value to that type's range, \
             so the comparison can never escape that bound. The branch \
             is dead — readers see a guard that does nothing, and the \
             real intended check (probably one digit different) is \
             missing. Compilers warn on this pattern; clippy elevates \
             it to an error in CI."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Drop the comparison or rewrite it against the original \
             pre-cast type. If the intent was a saturating bound, use \
             `value.min(MAX) as TargetTy` so the bound is explicit."
                .into(),
        ),
        snippet: snippet.to_owned(),
        weight: 4,
    })
}
