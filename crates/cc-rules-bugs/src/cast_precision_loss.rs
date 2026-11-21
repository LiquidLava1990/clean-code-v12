//! `cc.bug.cast_precision_loss` — wide-int-to-float cast that loses
//! precision because the float mantissa is narrower than the integer.
//!
//! Canonical bug:
//! ```text
//! let n: i64 = ledger();
//! let f = n as f32;     // f32 mantissa is 24 bits; >2^24 loses bits
//! let big: i128 = total();
//! let g = big as f64;   // f64 mantissa is 53 bits; >2^53 loses bits
//! ```
//! The cast compiles silently, but the resulting float cannot
//! represent every integer in the source range. Comparisons and
//! round-trip operations subsequently break in ways that look like
//! "off-by-one" bugs miles from the original cast.
//!
//! OSS source: clippy `cast_precision_loss`.
//!
//! Phase-9 source-byte heuristic: detect `<binding> as f32` where the
//! binding was declared `i64 / i128 / u64 / u128 / isize / usize`, and
//! `<binding> as f64` where the binding was declared `i128 / u128`.
//!
//! Confidence 0.85 — the heuristic ignores rebindings.

use std::collections::HashMap;

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, identifier_ending_at, is_test_file_path, looks_like_rule_pack_source,
    BugFindingBlueprint,
};

/// Family-3 probe R-CAST-PRECISION-LOSS.
#[derive(Debug, Default, Clone, Copy)]
pub struct CastPrecisionLossRule;

/// Source integer types that can lose precision when cast to f32 (24-bit
/// mantissa).
const F32_RISKY: &[&str] = &["u32", "u64", "u128", "i32", "i64", "i128", "usize", "isize"];

/// Source integer types that can lose precision when cast to f64 (53-bit
/// mantissa).
const F64_RISKY: &[&str] = &["u64", "u128", "i64", "i128"];

const TRACKED_TYPES: &[&str] = &["u32", "u64", "u128", "i32", "i64", "i128", "usize", "isize"];

impl Rule for CastPrecisionLossRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.cast_precision_loss"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "wide-int-to-float cast loses precision in the float mantissa"
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

struct PrecisionLossSite {
    name: String,
    src: &'static str,
    dst: &'static str,
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let mut bindings: HashMap<String, &'static str> = HashMap::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        record_bindings(line, &mut bindings);
        if let Some(site) = detect_precision_loss(line, &bindings) {
            out.push(emit(path.clone(), idx + 1, line, &site));
        }
    }
}

fn record_bindings(line: &str, bindings: &mut HashMap<String, &'static str>) {
    for ty in TRACKED_TYPES {
        let needle = format!(": {ty}");
        let mut start = 0;
        while let Some(idx) = line[start..].find(&needle) {
            let absolute = start + idx;
            if let Some(name) = identifier_ending_at(line, absolute) {
                bindings.insert(name.to_owned(), *ty);
            }
            start = absolute + needle.len();
        }
    }
}

fn detect_precision_loss(
    line: &str,
    bindings: &HashMap<String, &'static str>,
) -> Option<PrecisionLossSite> {
    for (dst, risky_set) in [("f32", F32_RISKY), ("f64", F64_RISKY)] {
        let needle = format!(" as {dst}");
        let Some(idx) = line.find(&needle) else {
            continue;
        };
        let after = idx + needle.len();
        if let Some(b) = line.as_bytes().get(after).copied() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                continue;
            }
        }
        let pre = &line[..idx];
        let Some(name) = identifier_ending_at(pre, pre.len()) else {
            continue;
        };
        if let Some(src) = bindings.get(name) {
            if risky_set.contains(src) {
                return Some(PrecisionLossSite {
                    name: name.to_owned(),
                    src,
                    dst,
                });
            }
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, site: &PrecisionLossSite) -> Finding {
    let PrecisionLossSite { name, src, dst } = site;
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let mantissa = if *dst == "f32" { 24 } else { 53 };
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.cast_precision_loss",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`{name} as {dst}` loses precision — `{src}` exceeds the {mantissa}-bit mantissa"
        ),
        explanation: format!(
            "`{name}` was declared as `{src}`. Casting to `{dst}` is \
             silent, but values larger than 2^{mantissa} cannot be \
             represented exactly: the float gets the closest \
             representable neighbour. Round-tripping back to integer \
             then disagrees with the original by 1 or more, which \
             surfaces as off-by-one bugs in callers that compare ids, \
             checksums, or accumulators."
        ),
        remediation: Remediation::SuggestedRewrite(
            "If you need exact arithmetic on the integer, keep it in \
             integer form. If you need a float, document the precision \
             loss and use `f64` where possible. For mantissa-sized \
             values, gate on `value < (1 << M)` before the cast and \
             return a typed error otherwise."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
