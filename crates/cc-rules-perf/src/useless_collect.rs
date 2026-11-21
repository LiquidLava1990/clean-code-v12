//! `cc.perf.useless_collect` — `.collect::<Vec<_>>()` immediately fed
//! into another iterator adapter.
//!
//! Canonical bug:
//! ```text
//! let upper: Vec<_> = items.iter().map(uppercase).collect();
//! for u in upper.iter() { ... }                           // useless intermediate
//!
//! items.iter().filter(p).collect::<Vec<_>>().into_iter()  // collect-then-uncollect
//! ```
//! `.collect()` allocates a `Vec`, fills it, then we immediately
//! re-iterate. The intermediate vector is pure overhead — `.iter()` /
//! `.into_iter()` would have produced the same final iterator
//! directly off the upstream chain.
//!
//! OSS source: clippy `needless_collect`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for the pattern
//! `.collect[::<...>]?().iter()` or `.collect[::<...>]?().into_iter()`
//! on a single line. Skip test files and rule-pack source.
//!
//! Severity `Required`, confidence 0.9.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_rust_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 probe R-USELESS-COLLECT.
#[derive(Debug, Default, Clone, Copy)]
pub struct UselessCollectRule;

const TAILS: &[&str] = &[".iter()", ".into_iter()", ".iter_mut()"];

impl Rule for UselessCollectRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.useless_collect"
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
        "`.collect()` immediately followed by `.iter()` / `.into_iter()`"
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
        if let Some(tail) = detect_useless_collect(line) {
            out.push(emit(path.clone(), idx + 1, line, tail));
        }
    }
}

/// Returns the matched tail (`.iter()` / `.into_iter()` /
/// `.iter_mut()`) when the line carries a `.collect(...)<tail>`
/// pattern.
fn detect_useless_collect(line: &str) -> Option<&'static str> {
    let mut search_start = 0_usize;
    while let Some(rel) = line[search_start..].find(".collect") {
        let abs = search_start + rel;
        let after_collect = abs + ".collect".len();
        let close_paren = find_collect_close(line, after_collect)?;
        let after_paren = close_paren + 1;
        for tail in TAILS {
            if line[after_paren..].starts_with(tail) {
                return Some(tail);
            }
        }
        search_start = after_paren;
    }
    None
}

/// Given the byte index just past `.collect`, return the index of the
/// matching `)`. Handles optional turbofish `::<Vec<_>>()` between
/// `.collect` and `(`.
fn find_collect_close(line: &str, mut cursor: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    if cursor >= bytes.len() {
        return None;
    }
    if bytes[cursor] == b':' {
        cursor = skip_turbofish(line, cursor)?;
    }
    if cursor >= bytes.len() || bytes[cursor] != b'(' {
        return None;
    }
    match_balanced(bytes, cursor, b'(', b')')
}

fn skip_turbofish(line: &str, start: usize) -> Option<usize> {
    if !line[start..].starts_with("::<") {
        return None;
    }
    let inner_start = start + "::<".len() - 1; // position of `<`
    let close = match_balanced(line.as_bytes(), inner_start, b'<', b'>')?;
    Some(close + 1)
}

/// Walk forward over `bytes` from `start` (which must point at
/// `open`), tracking nesting via `open` / `close` and return the index
/// of the matching `close`.
fn match_balanced(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0_i32;
    for (offset, &b) in bytes.iter().enumerate().skip(start) {
        depth += step_depth(b, open, close);
        if b == close && depth == 0 {
            return Some(offset);
        }
    }
    None
}

const fn step_depth(b: u8, open: u8, close: u8) -> i32 {
    if b == open {
        1
    } else if b == close {
        -1
    } else {
        0
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, tail: &'static str) -> Finding {
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
        rule_id: "cc.perf.useless_collect",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`.collect()` followed by `{tail}` allocates a `Vec` solely to re-iterate it"
        ),
        explanation: "`.collect()` materialises the upstream iterator into a \
             freshly allocated `Vec`, then `.iter()` / `.into_iter()` \
             immediately walks back through that `Vec` element by \
             element. The intermediate allocation is pure overhead — \
             the same downstream code can run directly off the \
             upstream iterator chain."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the `.collect()` (and any preceding turbofish). \
             The pipeline runs lazily until the *real* terminal — \
             `.for_each(...)` / `.fold(...)` / a `for ... in` loop / \
             a fan-in `.sum()` — without the intermediate `Vec`."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
