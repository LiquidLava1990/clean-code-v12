//! `cc.bug.bad_bit_mask` — bit-mask comparison whose result is
//! trivially knowable.
//!
//! Canonical bug:
//! ```text
//! if x & 0 == 1 { /* always false: 0 == 1 is impossible */ }
//! if x | 0xff != 0 { /* always true: result is at least 0xff */ }
//! if x & 0 > 0 { /* always false */ }
//! ```
//! The author meant a real mask check (e.g. `x & FLAG != 0`) but
//! mistyped the constant. The branch is dead and the real check is
//! missing.
//!
//! OSS source: clippy `bad_bit_mask`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for `<expr> & 0
//! <cmp> <lit>` and `<expr> | 0xff... <cmp> 0` shapes. Skip test files
//! and rule-pack source.
//!
//! Confidence 0.95 — pattern is sharp; the LHS of `& 0` always yields
//! zero regardless of `x`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-BAD-BIT-MASK.
#[derive(Debug, Default, Clone, Copy)]
pub struct BadBitMaskRule;

impl Rule for BadBitMaskRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.bad_bit_mask"
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
        "bit-mask comparison whose result is statically determined"
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
        if let Some(reason) = detect_bad_mask(line) {
            out.push(emit(path.clone(), idx + 1, line, reason));
        }
    }
}

/// Returns the reason string when the line carries a known dead mask
/// pattern. None when the line is fine.
fn detect_bad_mask(line: &str) -> Option<&'static str> {
    if has_and_zero_compare(line) {
        return Some("`x & 0` is always 0, so the comparison is dead");
    }
    if has_or_full_compare_zero(line) {
        return Some("`x | <full-mask>` is always non-zero, so the comparison is dead");
    }
    None
}

/// Pattern: `<expr> & 0 <cmp> <lit>` (zero on either side of the `&`).
/// The `0` must be bounded — it is the literal zero, not the prefix
/// of `0x1` / `0b10` / `01` etc.
fn has_and_zero_compare(line: &str) -> bool {
    if find_bounded_zero_compare(line, "& ").is_some() {
        return true;
    }
    if find_bounded_zero_compare(line, "&").is_some() {
        return true;
    }
    if find_zero_then_amp_compare(line).is_some() {
        return true;
    }
    false
}

/// Find `<prefix>0<bound> <cmp> <lit>` where `<bound>` is anything that
/// disambiguates the `0` from a longer numeric literal (whitespace,
/// closing paren, comparison operator, end-of-line).
fn find_bounded_zero_compare(line: &str, prefix: &str) -> Option<()> {
    let mut search = 0;
    while let Some(rel) = line[search..].find(prefix) {
        let zero_idx = search + rel + prefix.len();
        let bytes = line.as_bytes();
        if bytes.get(zero_idx).copied() != Some(b'0') {
            search = search + rel + 1;
            continue;
        }
        let after_zero = bytes.get(zero_idx + 1).copied();
        let bounded = match after_zero {
            None => true,
            Some(b) => !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.'),
        };
        if !bounded {
            search = search + rel + 1;
            continue;
        }
        let tail = &line[zero_idx + 1..];
        if next_comparison(tail).is_some() {
            return Some(());
        }
        search = search + rel + 1;
    }
    None
}

/// Pattern `0 & ... <cmp> ...` — zero literal as LHS of `&`.
fn find_zero_then_amp_compare(line: &str) -> Option<()> {
    let mut search = 0;
    while let Some(rel) = line[search..].find("0 &") {
        let absolute = search + rel;
        let before = if absolute == 0 {
            None
        } else {
            line.as_bytes().get(absolute - 1).copied()
        };
        let unbounded_before =
            before.is_some_and(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
        if unbounded_before {
            search = absolute + 1;
            continue;
        }
        let tail = &line[absolute + 3..];
        if next_comparison(tail).is_some() {
            return Some(());
        }
        search = absolute + 1;
    }
    None
}

/// Pattern: `<expr> | <full-mask> <cmp> 0` — anything OR'd with a
/// non-zero literal can never be zero.
fn has_or_full_compare_zero(line: &str) -> bool {
    let Some(pipe_idx) = line.find('|') else {
        return false;
    };
    if line.as_bytes().get(pipe_idx + 1).copied() == Some(b'|') {
        return false; // logical or
    }
    if pipe_idx > 0 && line.as_bytes()[pipe_idx - 1] == b'|' {
        return false;
    }
    let after = &line[pipe_idx + 1..];
    let Some(lit) = parse_leading_unsigned_literal(after) else {
        return false;
    };
    if lit == 0 {
        return false;
    }
    let rest = skip_literal(after);
    let Some((op, cmp_lit)) = next_comparison(rest) else {
        return false;
    };
    matches!(op, "==" | "!=" | "<" | "<=" | ">") && cmp_lit == 0
}

/// Parse `0 | 0x... | 0o... | 0b...` from the leading non-whitespace of
/// `s`. Returns the value as u128 — typed bit masks fit comfortably.
fn parse_leading_unsigned_literal(s: &str) -> Option<u128> {
    let t = s.trim_start();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return parse_radix(hex, 16);
    }
    if let Some(oct) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O")) {
        return parse_radix(oct, 8);
    }
    if let Some(bin) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        return parse_radix(bin, 2);
    }
    parse_radix(t, 10)
}

fn parse_radix(rest: &str, radix: u32) -> Option<u128> {
    let end = rest
        .find(|c: char| !(c.is_digit(radix) || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let digits: String = rest[..end].chars().filter(|c| *c != '_').collect();
    u128::from_str_radix(&digits, radix).ok()
}

fn skip_literal(s: &str) -> &str {
    let trimmed = s.trim_start();
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    if trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || trimmed.starts_with("0o")
        || trimmed.starts_with("0O")
        || trimmed.starts_with("0b")
        || trimmed.starts_with("0B")
    {
        i += 2;
    }
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    &trimmed[i..]
}

/// Locate the next comparison operator + its RHS literal.
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
        let lit = parse_signed_literal(after)?;
        return Some((op, lit));
    }
    None
}

fn parse_signed_literal(after: &str) -> Option<i128> {
    let trimmed = after.trim_start();
    let (sign, rest) = if let Some(rest) = trimmed.strip_prefix('-') {
        (-1_i128, rest.trim_start())
    } else {
        (1_i128, trimmed)
    };
    let lit = parse_leading_unsigned_literal(rest)?;
    let signed = i128::try_from(lit).ok()?;
    Some(sign * signed)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, reason: &'static str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.bad_bit_mask",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "bit-mask comparison is statically determined".into(),
        explanation: format!(
            "{reason}. The branch is dead — readers see a guard that \
             does nothing, and the real intended check (probably one \
             constant different) is missing. Compilers warn on this \
             pattern; clippy elevates it to an error in CI."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the constant with the actual flag/mask you meant \
             to test (e.g. `x & FLAG_READY != 0`). If the branch was \
             scaffolding, delete it."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
