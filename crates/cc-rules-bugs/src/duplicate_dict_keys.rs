//! `cc.bug.duplicate_dict_keys` — object literal with duplicate keys.
//!
//! Python `{"a": 1, "a": 2}` and JavaScript `{ a: 1, a: 2 }` shape
//! literals each carry a single key — the *second* assignment silently
//! shadows the first. Always a bug: either the author meant two
//! different keys, or the duplication is leftover dead code.
//!
//! - **Python**: ruff F601 / pyflakes F601.
//! - **JavaScript / TypeScript**: ESLint `no-dupe-keys`.
//!
//! Phase-10 source-byte heuristic: scan supported files for `{ ... }`
//! object literals on a single line (or short multi-line — bounded by
//! brace depth) and check for duplicate quoted-string or
//! bare-identifier keys. Confidence 0.95 — the pattern is unambiguous.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};
use std::collections::BTreeSet;

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.duplicate_dict_keys`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DuplicateDictKeysRule;

const SUPPORTED_EXTS: &[&str] = &["py", "js", "jsx", "ts", "tsx", "mjs", "cjs"];

impl Rule for DuplicateDictKeysRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.duplicate_dict_keys"
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
        "object/dict literal contains the same key twice — second value silently shadows first"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_ext(&path) {
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

fn is_supported_ext(path: &Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| SUPPORTED_EXTS.iter().any(|e| *e == ext))
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
        if let Some(dup) = find_duplicate_key_on_line(line) {
            out.push(emit(path.clone(), idx + 1, line, &dup));
        }
    }
}

/// Return the first duplicated key in a `{ ... }` segment of `line`, or
/// `None` if no duplicates are present. Single-line scope only —
/// multi-line literals are out of Phase-10 scope (the AST-aware version
/// lands in Phase 12).
fn find_duplicate_key_on_line(line: &str) -> Option<String> {
    let segment = brace_segment(line)?;
    let keys = extract_keys(segment);
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for k in &keys {
        if !seen.insert(k.as_str()) {
            return Some(k.clone());
        }
    }
    None
}

/// Return the substring between the first `{` and the matching `}` on
/// the same line, or `None` when no balanced braces appear.
fn brace_segment(line: &str) -> Option<&str> {
    let start = line.find('{')?;
    let after = &line[start + 1..];
    let end = after.find('}')?;
    Some(&after[..end])
}

/// Extract `key:` tokens from `segment`. Keys may be:
///   - quoted strings: `"foo"` or `'foo'`
///   - bare identifiers: `foo`
/// We look for `<key>:` separated by `,`. Keeps the implementation
/// linear over the segment.
fn extract_keys(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let parts = split_top_level_commas(segment);
    for part in parts {
        let trimmed = part.trim();
        let Some((key_part, _)) = trimmed.split_once(':') else {
            continue;
        };
        let key_trimmed = key_part.trim();
        if let Some(unquoted) = unquote(key_trimmed) {
            out.push(unquoted.to_owned());
        } else if is_identifier(key_trimmed) {
            out.push(key_trimmed.to_owned());
        }
    }
    out
}

fn split_top_level_commas(segment: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut last = 0;
    for (i, ch) in segment.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&segment[last..i]);
                last = i + 1;
            }
            _ => {}
        }
    }
    if last < segment.len() {
        out.push(&segment[last..]);
    }
    out
}

fn unquote(s: &str) -> Option<&str> {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return Some(&s[1..s.len() - 1]);
    }
    None
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, dup: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.duplicate_dict_keys",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "duplicate key `{dup}` in object/dict literal — second value shadows first"
        ),
        explanation: "Python and JavaScript collapse duplicate keys in a \
             single literal, keeping only the last value. Either the \
             author meant two different keys (typo) or this is leftover \
             dead code from a merge. Both shapes are bugs."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Rename one of the keys, or delete the redundant entry. If \
             the values genuinely need to share a key, build the \
             collection imperatively with a comment explaining which \
             value wins."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
