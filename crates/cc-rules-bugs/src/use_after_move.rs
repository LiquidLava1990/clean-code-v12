//! `cc.bug.use_after_move` — Rust binding consumed and then re-used.
//!
//! Rust's move semantics make `consume(x); use(x);` a compile-time
//! error in most contexts, but the kernel's frontend still runs against
//! files that intentionally violate the borrow checker (rule packs,
//! examples, doc tests) and against macro-generated bodies where the
//! original move is hidden behind a token tree.
//!
//! OSS source: `clang-tidy` `bugprone-use-after-move` (the C++ analogue;
//! the Rust spelling is the same logical pattern).
//!
//! Phase-8 conservative byte-scan (`.rs` only): for each line carrying
//! a known consuming pattern (`drop(x)`, `mem::take(x)`, `_ = x`,
//! `x.into_iter()`, …), record the moved identifier; if a later line
//! references the same identifier, fire. Bound: 200-line search
//! window per move site to avoid mass false positives in long files.
//!
//! Confidence 0.85 — the heuristic deliberately ignores rebindings
//! (`let x = ...;` after the move) because the kernel cannot resolve
//! shadowing without scope information.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-USE-AFTER-MOVE.
#[derive(Debug, Default, Clone, Copy)]
pub struct UseAfterMoveRule;

/// How many lines after the move site we scan for a re-use.
const SEARCH_WINDOW_LINES: usize = 200;

/// Consuming patterns. Each is a function `&str -> Option<&str>` that
/// returns the moved identifier when the line matches.
type ConsumePattern = fn(&str) -> Option<&str>;

const CONSUME_PATTERNS: &[ConsumePattern] = &[
    pattern_drop,
    pattern_consume,
    pattern_mem_take,
    pattern_underscore_assign,
    pattern_into_iter_chain,
];

impl Rule for UseAfterMoveRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.use_after_move"
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
        "value used after a known consuming call"
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
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(name) = consumed_identifier(trimmed) else {
            continue;
        };
        if let Some(reuse_line) = find_reuse(&lines, idx, name) {
            out.push(emit(path.clone(), idx + 1, reuse_line + 1, line, name));
        }
    }
}

fn consumed_identifier(trimmed: &str) -> Option<&str> {
    for pat in CONSUME_PATTERNS {
        if let Some(name) = pat(trimmed) {
            if !name.is_empty() && is_simple_ident(name) {
                return Some(name);
            }
        }
    }
    None
}

fn pattern_drop(line: &str) -> Option<&str> {
    extract_call_arg(line, "drop(")
}

fn pattern_consume(line: &str) -> Option<&str> {
    extract_call_arg(line, "consume(")
}

fn pattern_mem_take(line: &str) -> Option<&str> {
    extract_call_arg(line, "mem::take(").or_else(|| extract_call_arg(line, "std::mem::take("))
}

/// `_ = x;` style suppression — discards x by-value.
fn pattern_underscore_assign(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("_ = ")?;
    let name_end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
    let name = &rest[..name_end];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// `let it = x.into_iter()` — consumes x.
fn pattern_into_iter_chain(line: &str) -> Option<&str> {
    let dot_idx = line.find(".into_iter()")?;
    let prefix = &line[..dot_idx];
    let mut start = prefix.len();
    let bytes = prefix.as_bytes();
    while start > 0 && is_ident_char(bytes[start - 1] as char) {
        start -= 1;
    }
    let name = &prefix[start..];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_call_arg<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let idx = line.find(prefix)?;
    let after = &line[idx + prefix.len()..];
    let close = after.find(')')?;
    Some(after[..close].trim())
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && name.chars().all(is_ident_char)
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn find_reuse(lines: &[&str], move_idx: usize, name: &str) -> Option<usize> {
    let end = (move_idx + 1 + SEARCH_WINDOW_LINES).min(lines.len());
    let mut depth: i32 = 0;
    for (offset, line) in lines[move_idx + 1..end].iter().enumerate() {
        depth += brace_delta(line);
        if depth < 0 {
            // Walked out of the enclosing block — the identifier we
            // saw consumed has gone out of scope. Stop scanning.
            return None;
        }
        if line_rebinds(line, name) {
            return None;
        }
        if line_uses_identifier(line, name) {
            return Some(move_idx + 1 + offset);
        }
    }
    None
}

fn brace_delta(line: &str) -> i32 {
    let mut depth: i32 = 0;
    let mut in_str: Option<char> = None;
    let mut prev: char = ' ';
    for c in line.chars() {
        if let Some(quote) = in_str {
            if c == quote && prev != '\\' {
                in_str = None;
            }
        } else {
            match c {
                '"' | '\'' => in_str = Some(c),
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
        prev = c;
    }
    depth
}

fn line_rebinds(line: &str, name: &str) -> bool {
    let needle = format!("let {name}");
    line.trim_start().starts_with(&needle)
}

fn line_uses_identifier(line: &str, name: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = line[start..].find(name) {
        let absolute = start + idx;
        let before = absolute
            .checked_sub(1)
            .and_then(|i| line.as_bytes().get(i).copied());
        let after = line.as_bytes().get(absolute + name.len()).copied();
        let bordered = before.is_some_and(|b| is_ident_continuation_byte(b))
            || after.is_some_and(is_ident_continuation_byte);
        if !bordered {
            return true;
        }
        start = absolute + name.len();
    }
    false
}

fn is_ident_continuation_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn emit(path: Utf8PathBuf, move_line: usize, reuse_line: usize, line: &str, name: &str) -> Finding {
    let pos = Position::new(move_line as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.use_after_move",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name}` is used after a consuming call"),
        explanation: format!(
            "Line {move_line} consumes `{name}` (drop / mem::take / \
             into_iter / `_ = {name}`), then line {reuse_line} references \
             `{name}` again. The borrow checker rejects this in plain \
             code, but it slips through in macro-generated bodies and \
             unsafe blocks. The second use will read a moved-from value."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Reorder the calls so the use precedes the consume, clone \
             the value if both sites need ownership, or take a borrow \
             (`&value`) where ownership is not required."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
