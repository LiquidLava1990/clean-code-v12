//! `cc.bug.cast_possible_truncation` — narrowing integer cast where
//! the source type is wider than the destination.
//!
//! Canonical bug:
//! ```text
//! let n: u64 = huge();
//! let small = n as u8;     // silently truncates anything > 0xff
//! let i: i64 = signed();
//! let i2 = i as i32;       // wraps for |i| > i32::MAX
//! ```
//! Rust's `as` cast on integers is documented as truncating, but the
//! behaviour is silent: callers who expected a `TryFrom` validation
//! receive corrupted data.
//!
//! OSS source: clippy `cast_possible_truncation`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for `<binding>` that
//! declares the source type, then later `<binding> as <narrower_ty>`
//! cast on the same line or within a 50-line window. We track the
//! type from the immediately-preceding `let <name>: <wide_ty>` /
//! `<name>: <wide_ty>` parameter declaration. Confidence 0.85 — the
//! heuristic ignores rebindings and complex generic flow.

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

/// Family-3 probe R-CAST-POSSIBLE-TRUNCATION.
#[derive(Debug, Default, Clone, Copy)]
pub struct CastPossibleTruncationRule;

const WIDE_TYPES: &[&str] = &["u128", "u64", "i128", "i64", "usize", "isize"];
const NARROW_TYPES: &[&str] = &["u8", "u16", "u32", "i8", "i16", "i32"];

impl Rule for CastPossibleTruncationRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.cast_possible_truncation"
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
        "narrowing integer cast that may silently truncate"
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

struct TruncationSite {
    name: String,
    wide: &'static str,
    narrow: &'static str,
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
        if let Some(site) = detect_truncation(line, &bindings) {
            out.push(emit(path.clone(), idx + 1, line, &site));
        }
    }
}

/// Track `let <name>: <wide_ty>` and `fn ...(<name>: <wide_ty>, ...)`
/// declarations, recording the wide-type association.
fn record_bindings(line: &str, bindings: &mut HashMap<String, &'static str>) {
    for ty in WIDE_TYPES {
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

/// Returns the truncation site when the line has a narrowing cast on
/// a binding whose source type we know is wide.
fn detect_truncation(
    line: &str,
    bindings: &HashMap<String, &'static str>,
) -> Option<TruncationSite> {
    for narrow in NARROW_TYPES {
        let needle = format!(" as {narrow}");
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
        if let Some(wide) = bindings.get(name) {
            return Some(TruncationSite {
                name: name.to_owned(),
                wide,
                narrow,
            });
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, site: &TruncationSite) -> Finding {
    let TruncationSite { name, wide, narrow } = site;
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
        rule_id: "cc.bug.cast_possible_truncation",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name} as {narrow}` may silently truncate from `{wide}`"),
        explanation: format!(
            "`{name}` was declared as `{wide}` and is being cast to \
             `{narrow}` with `as`. Rust's `as` cast on integers \
             silently truncates the high bits — values that exceed the \
             destination range produce an arbitrary low-bit pattern \
             instead of a compile-time or runtime error."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Use `{narrow}::try_from({name})?` to fail loudly when \
                 the value does not fit, or `{name}.min({narrow}::MAX \
                 as {wide}) as {narrow}` to clamp explicitly. Reserve \
                 plain `as` casts for cases where truncation is the \
                 intended behaviour and document the rationale."
        )),
        snippet,
        weight: 4,
    })
}
