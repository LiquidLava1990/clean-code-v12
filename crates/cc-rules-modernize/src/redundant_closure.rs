//! `cc.modernize.redundant_closure` — `.map(|x| f(x))` superseded by
//! `.map(f)`.
//!
//! Canonical pattern:
//! ```text
//! items.iter().map(|s| String::from(s)).collect()      // |s| f(s)
//! ids.iter().filter(|n| is_even(n)).count()            // |n| f(n)
//! values.into_iter().for_each(|v| process(v));         // |v| f(v)
//! ```
//! When a closure's only job is to forward its single argument to a
//! single-arg callable, the closure adds nothing — the function value
//! itself is already a `FnMut(T) -> U`. Inlining lets the optimiser
//! see through one fewer indirection and reads more directly.
//!
//! OSS source: clippy `redundant_closure`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for the literal
//! pattern `|<arg>| <fn>(<arg>)` where `<arg>` is the same identifier
//! on both sides and `<fn>` is a single (possibly path-qualified)
//! identifier. Skip test files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.9.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.redundant_closure`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedundantClosureRule;

impl Rule for RedundantClosureRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.redundant_closure"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "single-arg closure that just forwards to a single-arg fn"
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
        if let Some((arg, fn_name)) = detect_redundant_closure(line) {
            out.push(emit(path.clone(), idx + 1, line, &arg, &fn_name));
        }
    }
}

/// Returns `(arg, fn_name)` when the line carries `|<arg>| <fn>(<arg>)`.
fn detect_redundant_closure(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    let mut search_start = 0_usize;
    while let Some(rel) = line[search_start..].find('|') {
        let abs = search_start + rel;
        search_start = abs + 1;
        if let Some(pair) = try_match_at(bytes, abs) {
            return Some(pair);
        }
    }
    None
}

/// Try to match `|<arg>| <fn>(<arg>)` starting at the given `|` byte.
fn try_match_at(bytes: &[u8], pipe_idx: usize) -> Option<(String, String)> {
    let line = std::str::from_utf8(bytes).ok()?;
    let after_pipe = &line[pipe_idx + 1..];
    let arg_end = after_pipe.find('|')?;
    let arg = after_pipe[..arg_end].trim();
    if arg.is_empty() || !is_simple_ident(arg) {
        return None;
    }
    let after_arg = after_pipe[arg_end + 1..].trim_start();
    let (fn_name, rest) = take_path_ident(after_arg)?;
    if fn_name.is_empty() {
        return None;
    }
    if !rest.starts_with('(') {
        return None;
    }
    let close_paren = find_matching_paren(rest)?;
    let inner = rest[1..close_paren].trim();
    if inner != arg {
        return None;
    }
    Some((arg.to_owned(), fn_name.to_owned()))
}

fn is_simple_ident(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Take a possibly path-qualified identifier (`Foo::bar`, `module::baz`).
/// Returns `(ident, rest)` or `None` when nothing matched.
fn take_path_ident(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut end = 0_usize;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_alphanumeric() || b == b'_' {
            end += 1;
            continue;
        }
        if b == b':' && bytes.get(end + 1) == Some(&b':') {
            end += 2;
            continue;
        }
        break;
    }
    if end == 0 {
        return None;
    }
    Some((&s[..end], &s[end..]))
}

fn find_matching_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return None;
    }
    let mut depth = 0_i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, arg: &str, fn_name: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.redundant_closure",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`|{arg}| {fn_name}({arg})` adds no value — pass `{fn_name}` directly"),
        explanation: format!(
            "When a closure's only job is to forward its single \
             argument to `{fn_name}`, the closure is pure overhead. \
             `{fn_name}` is already a `FnMut({arg}) -> _` and binds \
             at the iterator-adapter call site directly. Removing the \
             closure also lets the optimiser see one fewer level of \
             indirection."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `|{arg}| {fn_name}({arg})` with `{fn_name}`. \
                 If `{fn_name}` is a method, write `Type::{fn_name}` \
                 (or the short form when the receiver is unambiguous)."
        )),
        snippet,
        weight: 1,
    })
}
