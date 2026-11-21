//! `cc.bug.shift_amount_oor` — bit-shift expression with a constant shift
//! amount ≥ 32. In every supported language, shifting an `i32` / `int`
//! by 32 or more is undefined or implementation-defined behaviour:
//!
//! - C / C++: undefined behaviour.
//! - Rust: panics in debug, wraps in release.
//! - Java / C#: shift amount is masked (`& 31` for `int`) — so `x << 32`
//!   silently degrades to `x << 0`.
//! - JS / TS: shift amount is masked to the low 5 bits — same silent
//!   no-op.
//! - Python: yields a perfectly fine giant int, but if the result is
//!   later truncated to 32 bits the bug surfaces downstream.
//!
//! Phase-7 conservative: detect literal shift amount `>= 32` in the
//! source bytes, regardless of language. Type-aware refinement (e.g.
//! 64-bit shifts where 32 is fine) is deferred to the type-aware pack.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-SHIFT-OOR.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShiftAmountOorRule;

const SHIFT_OPS: &[&str] = &["<<", ">>"];
const MIN_OOR: u32 = 32;

impl Rule for ShiftAmountOorRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.shift_amount_oor"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "bit-shift constant amount >= 32 is undefined or silently masked"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if is_comment_line(trimmed) {
            continue;
        }
        if let Some(hit) = find_shift_oor(line) {
            out.push(emit(path.clone(), line_idx + 1, &hit));
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

#[derive(Debug)]
pub(crate) struct ShiftHit {
    pub(crate) operator: &'static str,
    pub(crate) amount: u32,
    pub(crate) snippet: String,
}

fn find_shift_oor(line: &str) -> Option<ShiftHit> {
    SHIFT_OPS
        .iter()
        .filter_map(|op| try_match_shift(line, op))
        .find(|hit| is_oversized_shift(hit.amount))
}

/// Attempt to match `op` in `line` and parse the trailing literal
/// shift amount. Returns `None` when `op` is absent, no literal
/// follows it, or the literal does not parse as `u32`.
pub(crate) fn try_match_shift(line: &str, op: &&'static str) -> Option<ShiftHit> {
    let idx = line.find(*op)?;
    let after = &line[idx + op.len()..];
    let amount = parse_shift_amount(after)?;
    Some(ShiftHit {
        operator: op,
        amount,
        snippet: line.trim().to_owned(),
    })
}

/// Read the leading run of decimal digits from `after` (after stripping
/// whitespace) and parse as `u32`.
fn parse_shift_amount(after: &str) -> Option<u32> {
    leading_unsigned_literal(after)
}

/// Tier-0 shift policy: `>= 32` is at or beyond a 32-bit operand width.
const fn is_oversized_shift(amount: u32) -> bool {
    amount >= MIN_OOR
}

fn leading_unsigned_literal(suffix: &str) -> Option<u32> {
    let trimmed = suffix.trim_start();
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn emit(path: Utf8PathBuf, line_no: usize, hit: &ShiftHit) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.shift_amount_oor",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "bit-shift `{}` by {} is at or beyond 32-bit width",
            hit.operator, hit.amount
        ),
        explanation: format!(
            "A constant shift amount of {} is at or above the width of a \
             32-bit integer. Most languages mask the shift amount to the low \
             5 bits silently (Java / C# / JS / TS), or undefined-behave \
             (C / C++ / Rust release). The compiled program does not do what \
             the source suggests.",
            hit.amount
        ),
        remediation: Remediation::SuggestedRewrite(
            "If the operand is genuinely 64-bit, declare it as `i64` / `u64` \
             / `BigInt` first, then shift. If the shift amount is computed, \
             clamp it (`amount.min(31)`). If 32 was intended for a 32-bit \
             reset, use `0` directly — the result is identical."
                .into(),
        ),
        snippet: hit.snippet.clone(),
        weight: 3,
    })
}
