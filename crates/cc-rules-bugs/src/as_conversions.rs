//! `cc.bug.as_conversions` — `as` casts on numeric identifiers.
//!
//! Canonical bug:
//! ```text
//! let n: u64 = expensive();
//! let small = n as u8;            // silent truncation
//! let weight = idx as f64;        // i64 -> f64 may lose precision
//! ```
//! `as` is a hammer: it truncates, sign-extends, lossy-converts floats,
//! and saturates — all without a runtime check. Even when the
//! conversion happens to be safe today, the operator hides that intent
//! from the next reader. Prefer `From` / `TryFrom` / `try_into()` so
//! the conversion lattice stays visible at the call site.
//!
//! OSS source: clippy `as_conversions`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for
//! `<identifier> as <numeric_ty>` patterns. Skip pure literal casts
//! like `0u8 as u32` (already typed, no information lost). Skip test
//! files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.7.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, identifier_ending_at, is_test_file_path, looks_like_rule_pack_source,
    BugFindingBlueprint,
};

/// Family-3 probe R-AS-CONVERSIONS.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsConversionsRule;

const NUMERIC_TARGETS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64",
];

impl Rule for AsConversionsRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.as_conversions"
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
        "`as` cast on a numeric identifier hides truncation / precision loss"
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
        if let Some(target) = detect_as_cast(line) {
            out.push(emit(path.clone(), idx + 1, line, target));
        }
    }
}

/// Returns the target numeric type when the line has `<ident> as <ty>`
/// where `<ident>` is not a literal.
fn detect_as_cast(line: &str) -> Option<&'static str> {
    for target in NUMERIC_TARGETS {
        let needle = format!(" as {target}");
        let mut search_start = 0_usize;
        while let Some(rel) = line[search_start..].find(&needle) {
            let abs = search_start + rel;
            let after = abs + needle.len();
            let next_byte = line.as_bytes().get(after).copied().unwrap_or(b' ');
            search_start = after;
            if is_ident_continuation(next_byte) {
                continue; // `u32` / `usize` etc. — not our target
            }
            let ident_end = abs;
            let Some(ident) = identifier_ending_at(line, ident_end) else {
                continue;
            };
            if is_pure_numeric_literal(ident) {
                continue; // `0u8 as u32` — typed literal, skip
            }
            return Some(target);
        }
    }
    None
}

const fn is_ident_continuation(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True when `s` is purely digits / underscores / a numeric type
/// suffix — i.e. a literal already, no information is lost.
fn is_pure_numeric_literal(s: &str) -> bool {
    let stripped = strip_numeric_suffix(s);
    !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_digit() || c == '_')
}

fn strip_numeric_suffix(s: &str) -> &str {
    for target in NUMERIC_TARGETS {
        if let Some(rest) = s.strip_suffix(target) {
            return rest;
        }
    }
    s
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, target: &'static str) -> Finding {
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
        rule_id: "cc.bug.as_conversions",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`as {target}` cast hides the conversion choice"),
        explanation: "`as` is the universal numeric hammer: it truncates, \
             sign-extends, lossy-converts floats, and saturates — all \
             silently. Even if today's run happens to fit, the next \
             reader has to recompute the safety argument from scratch, \
             and a future change to either side becomes a silent \
             bug. Prefer the `From` / `TryFrom` / `try_into()` lattice \
             so the call site declares which conversion behaviour it \
             needs."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "If the conversion is infallible by construction, \
                 use `{target}::from(x)` (compile-time check). If it \
                 may fail, write `{target}::try_from(x)?` and \
                 surface the `TryFromIntError`. For deliberate \
                 truncation, mark intent explicitly with \
                 `(x & {target}::MAX as _) as {target}` and a \
                 comment."
        )),
        snippet,
        weight: 2,
    })
}
