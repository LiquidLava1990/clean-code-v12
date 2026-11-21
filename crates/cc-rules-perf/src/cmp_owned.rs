//! `cc.perf.cmp_owned` — comparing a borrowed string against a freshly
//! allocated owned `String` instead of a string slice.
//!
//! Canonical pattern:
//! ```text
//! if s == "literal".to_string() { ... }              // allocates, then drops
//! if s == String::from("literal") { ... }            // same
//! if name == format!("user_{}", id) { ... }          // unavoidable, but…
//! ```
//! Constructing an owned `String` purely so the `PartialEq` operator
//! has matching ownership is wasteful: each comparison allocates, then
//! immediately drops the heap buffer. `&str` versus `&str` compares
//! byte-by-byte without the allocator round-trip.
//!
//! OSS source: clippy `cmp_owned`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for an equality /
//! inequality operator whose RHS or LHS is a known String-construction
//! call: `.to_string()`, `String::from(...)`, `String::new()`,
//! `format!(...)`. Skip test files and rule-pack source.
//!
//! Confidence 0.9 — the patterns are sharp.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_rust_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 probe R-CMP-OWNED.
#[derive(Debug, Default, Clone, Copy)]
pub struct CmpOwnedRule;

const ALLOC_NEEDLES: &[&str] = &[
    ".to_string()",
    "String::from(",
    "String::new()",
    "format!(",
    "ToString::to_string(",
];

impl Rule for CmpOwnedRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.cmp_owned"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "comparison constructs a String per call instead of using &str"
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
            if is_rust_test_path(&path) || looks_like_rule_pack_source(&path) {
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
        if let Some(needle) = detect_cmp_owned(line) {
            out.push(emit(path.clone(), idx + 1, line, needle));
        }
    }
}

/// Returns the matched alloc needle when the line has a comparison
/// against a String-constructing expression.
fn detect_cmp_owned(line: &str) -> Option<&'static str> {
    let cmp_idx = find_eq_operator(line)?;
    let (lhs, rhs) = line.split_at(cmp_idx);
    let rhs = &rhs[2..]; // skip == or !=
    for needle in ALLOC_NEEDLES {
        if rhs.contains(needle) || lhs.contains(needle) {
            return Some(needle);
        }
    }
    None
}

/// Find the first `==` or `!=` outside of string / char literals. We
/// skip line comments and bracketed angle generics for safety.
fn find_eq_operator(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_str: Option<u8> = None;
    let mut prev = b' ';
    while i + 1 < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else {
            match c {
                b'"' | b'\'' => in_str = Some(c),
                b'=' if bytes[i + 1] == b'=' => return Some(i),
                b'!' if bytes[i + 1] == b'=' => return Some(i),
                _ => {}
            }
        }
        prev = c;
        i += 1;
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.cmp_owned",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("equality compares against a freshly allocated String (`{needle}`)"),
        explanation: "Each comparison allocates a heap buffer, copies the literal \
             into it, then drops it on the next instruction. The right \
             answer is to compare slices: `s == \"literal\"` (where `s` \
             is `&str` or auto-derefs via `AsRef<str>`). For a hot \
             path this is two allocator round-trips per call replaced \
             by a `memcmp`."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the `.to_string()` / `String::from(...)` / \
             `format!(...)` and compare slices: `s == \"literal\"`. If \
             the LHS is `&String`, deref with `*` or call `.as_str()` \
             before the compare."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
