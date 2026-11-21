//! `cc.bug.arithmetic_side_effects` — integer arithmetic operators
//! (`+`, `-`, `*`, `/`, `%`) used in security-sensitive code without
//! explicit overflow handling.
//!
//! Canonical bug:
//! ```text
//! #[deny(arithmetic_overflow)]
//! fn budget(used: u32, granted: u32) -> u32 {
//!     granted - used               // underflows silently in --release
//! }
//! ```
//! `+`, `-`, `*`, `/`, `%` panic in debug but wrap silently in
//! `--release`. Security-sensitive code must reach for the explicit
//! `checked_*`, `saturating_*`, or `wrapping_*` family so the overflow
//! decision is visible at the call site.
//!
//! OSS source: clippy `arithmetic_side_effects`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files. Conservative —
//! only flag a line carrying a binary `+`/`-`/`*`/`/`/`%` operator on
//! identifiers when the file (a) literally contains
//! `#[deny(arithmetic_overflow)]` somewhere above the line, or (b)
//! sits inside a security-sensitive crate (`cc-runtime/`,
//! `cc-foundation/`). Skip rule-pack source and test files.
//!
//! Severity `Nit`, confidence 0.7 — even gated, the heuristic stays
//! quiet by default.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-ARITHMETIC-SIDE-EFFECTS.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArithmeticSideEffectsRule;

const SECURITY_SENSITIVE_DIRS: &[&str] = &["/cc-runtime/", "/cc-foundation/"];
const DENY_ATTR: &str = "#[deny(arithmetic_overflow)]";

impl Rule for ArithmeticSideEffectsRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.arithmetic_side_effects"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "binary integer arithmetic in security-sensitive code without an overflow choice"
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

fn is_security_sensitive(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    SECURITY_SENSITIVE_DIRS.iter().any(|seg| s.contains(seg))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let security_sensitive = is_security_sensitive(path);
    let has_deny_attr = text.contains(DENY_ATTR);
    if !security_sensitive && !has_deny_attr {
        return;
    }
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if let Some(op) = detect_arith_op(line) {
            out.push(emit(path.clone(), idx + 1, line, op));
        }
    }
}

/// Returns the matched operator when the line carries an integer
/// arithmetic operator on identifiers.
fn detect_arith_op(line: &str) -> Option<&'static str> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_str: Option<u8> = None;
    let mut prev = b' ';
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
            prev = c;
            i += 1;
            continue;
        }
        if matches!(c, b'"' | b'\'') {
            in_str = Some(c);
        }
        if let Some(op) = match_binary_op(bytes, i, prev) {
            return Some(op);
        }
        prev = c;
        i += 1;
    }
    None
}

/// Match a binary `+`/`-`/`*`/`/`/`%` between identifier-flavoured
/// neighbours. Stays away from `+=`, `*=`, doc comments, attributes,
/// function pointers, etc.
fn match_binary_op(bytes: &[u8], i: usize, prev: u8) -> Option<&'static str> {
    let c = bytes[i];
    if !matches!(c, b'+' | b'-' | b'*' | b'/' | b'%') {
        return None;
    }
    let next = bytes.get(i + 1).copied().unwrap_or(b' ');
    if next == b'=' || next == c {
        return None; // +=, ==, **, //, etc.
    }
    if c == b'/' && (next == b'/' || next == b'*') {
        return None; // line / block comment
    }
    if c == b'*' && prev == b'&' {
        return None; // `&*` deref
    }
    if !is_ident_neighbour(bytes, i, NeighbourSide::Left)
        || !is_ident_neighbour(bytes, i, NeighbourSide::Right)
    {
        return None;
    }
    Some(op_label(c))
}

#[derive(Copy, Clone)]
enum NeighbourSide {
    Left,
    Right,
}

/// True iff the closest non-whitespace byte on `side` of `i` looks
/// like the end / start of an identifier expression.
fn is_ident_neighbour(bytes: &[u8], i: usize, side: NeighbourSide) -> bool {
    match side {
        NeighbourSide::Left => left_is_ident_end(bytes, i),
        NeighbourSide::Right => right_is_ident_start(bytes, i),
    }
}

fn left_is_ident_end(bytes: &[u8], i: usize) -> bool {
    let mut j = i;
    while j > 0 && bytes[j - 1] == b' ' {
        j -= 1;
    }
    j != 0 && is_ident_byte(bytes[j - 1])
}

fn right_is_ident_start(bytes: &[u8], i: usize) -> bool {
    let mut j = i + 1;
    while j < bytes.len() && bytes[j] == b' ' {
        j += 1;
    }
    if j >= bytes.len() {
        return false;
    }
    let b = bytes[j];
    b.is_ascii_alphanumeric() || b == b'_' || b == b'('
}

const fn op_label(c: u8) -> &'static str {
    match c {
        b'+' => "+",
        b'-' => "-",
        b'*' => "*",
        b'/' => "/",
        b'%' => "%",
        _ => "?",
    }
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b')' || b == b']'
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, op: &'static str) -> Finding {
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
        rule_id: "cc.bug.arithmetic_side_effects",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("binary `{op}` in security-sensitive code wraps silently in `--release`"),
        explanation: "Plain `+`, `-`, `*`, `/`, `%` panic in debug builds but \
             wrap (or trap-then-wrap) in `--release`. In a \
             security-sensitive crate that wrap can hand an attacker \
             a smaller-than-expected integer, a divide-by-zero, or a \
             sign flip that becomes a privilege boundary. Make the \
             overflow decision explicit with `checked_*`, \
             `saturating_*`, `wrapping_*`, or `overflowing_*`."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the bare arithmetic with the family that names \
             the desired behaviour: `a.checked_sub(b).ok_or(\
             Error::Underflow)?` for fail-fast, `a.saturating_sub(b)` \
             for clamp-to-zero, or `a.wrapping_sub(b)` when the wrap \
             is intentional and documented at the call site."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
