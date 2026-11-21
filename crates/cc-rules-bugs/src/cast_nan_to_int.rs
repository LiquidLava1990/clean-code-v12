//! `cc.bug.cast_nan_to_int` — casting `NaN` (or a NaN-producing
//! expression) to an integer type.
//!
//! Canonical bug:
//! ```text
//! let x: u32 = f64::NAN as u32;       // result is 0 — UB-adjacent
//! let y: i32 = (0.0f64 / 0.0) as i32; // 0 / 0 = NaN -> 0
//! ```
//! The result on stable Rust is 0, but the value is meaningless: every
//! NaN funnels into the same integer regardless of the upstream
//! computation, so subsequent comparisons / lookups silently agree on
//! a fictitious value.
//!
//! OSS source: clippy `cast_nan_to_int`.
//!
//! Phase-9 source-byte heuristic: detect on a `.rs` line either
//! `<expr> / 0.0 as <int_ty>`, `f32::NAN as <int_ty>`, `f64::NAN as
//! <int_ty>`, or any expression containing `NAN as <int_ty>`. Skip
//! test files and rule-pack source.
//!
//! Confidence 0.98 — these patterns are unambiguous.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-CAST-NAN-TO-INT.
#[derive(Debug, Default, Clone, Copy)]
pub struct CastNanToIntRule;

const INT_TARGETS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

impl Rule for CastNanToIntRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.cast_nan_to_int"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.98)
    }
    fn description(&self) -> &'static str {
        "casting a NaN-producing expression to an integer destroys the value"
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
        if let Some(pattern) = detect_nan_cast(line) {
            out.push(emit(path.clone(), idx + 1, line, pattern));
        }
    }
}

/// Returns the matched pattern label when the line contains a NaN cast.
fn detect_nan_cast(line: &str) -> Option<&'static str> {
    if has_nan_literal_cast(line) {
        return Some("`NAN as <int>`");
    }
    if has_zero_div_zero_cast(line) {
        return Some("`0.0 / 0.0 as <int>`");
    }
    None
}

fn has_nan_literal_cast(line: &str) -> bool {
    if !line.contains("NAN") && !line.contains("nan()") {
        return false;
    }
    line_has_int_cast(line)
}

fn has_zero_div_zero_cast(line: &str) -> bool {
    if !contains_zero_div_zero(line) {
        return false;
    }
    line_has_int_cast(line)
}

/// Match `0.0 / 0.0`, `0. / 0.`, `0_f32 / 0_f32`, etc.
fn contains_zero_div_zero(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'/' {
            let lhs = line[..i].trim_end();
            let rhs = line[i + 1..].trim_start();
            if is_zero_float_literal(lhs) && starts_with_zero_float_literal(rhs) {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_zero_float_literal(s: &str) -> bool {
    let s = s.trim_end_matches(|c: char| c == ')' || c == ' ');
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut start = bytes.len();
    while start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' {
            start -= 1;
        } else {
            break;
        }
    }
    let token = &s[start..];
    is_zero_float_token(token)
}

fn starts_with_zero_float_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        let c = bytes[end];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            end += 1;
        } else {
            break;
        }
    }
    is_zero_float_token(&s[..end])
}

fn is_zero_float_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    // Strip type suffix (f32 / f64).
    let core = token
        .strip_suffix("f32")
        .or_else(|| token.strip_suffix("f64"))
        .unwrap_or(token);
    let core = core.trim_end_matches('_');
    let stripped = core.replace('_', "");
    if stripped.is_empty() {
        return false;
    }
    let must_be_float = stripped.contains('.') || token.ends_with("f32") || token.ends_with("f64");
    if !must_be_float {
        return false;
    }
    stripped.chars().all(|c| c == '0' || c == '.')
}

fn line_has_int_cast(line: &str) -> bool {
    INT_TARGETS.iter().any(|ty| {
        let needle = format!("as {ty}");
        let Some(idx) = line.find(&needle) else {
            return false;
        };
        let after = idx + needle.len();
        line.as_bytes()
            .get(after)
            .copied()
            .is_none_or(|b: u8| !(b.is_ascii_alphanumeric() || b == b'_'))
    })
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, pattern: &str) -> Finding {
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
        rule_id: "cc.bug.cast_nan_to_int",
        severity: Severity::Required,
        confidence: Confidence::new(0.98),
        location,
        headline: format!("{pattern} silently produces 0 — the NaN information is destroyed"),
        explanation: "Casting a NaN-bearing float expression to an integer yields \
             0 on stable Rust regardless of the upstream computation. \
             Every divergent path collapses to the same integer, so \
             later comparisons / lookups silently agree on a fictitious \
             value. clippy treats this as undefined-behaviour-adjacent \
             because the platform defined behaviour was reached only as \
             of Rust 1.45 — older toolchains and cross-compiled targets \
             still observe true UB."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Check for NaN before the cast: `if x.is_nan() { return \
             Err(...) } else { x as TargetTy }`. Or use the saturating \
             cast: `x.try_into().ok()` / `x.clamp(min, max) as \
             TargetTy` after a NaN guard."
                .into(),
        ),
        snippet,
        weight: 6,
    })
}
