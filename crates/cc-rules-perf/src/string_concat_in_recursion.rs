//! `cc.perf.string_concat_in_recursion` — Python / JS / TS function
//! that builds a string with `s = s + ...` (or `s += ...`) and recurses
//! on itself.
//!
//! Canonical bug:
//! ```python
//! def collect(node, acc=""):
//!     acc = acc + node.value
//!     for child in node.children:
//!         acc = collect(child, acc)
//!     return acc
//! ```
//! Each recursive call allocates a fresh string for the concat. Total
//! work is quadratic in the tree size. The companion
//! [`crate::string_concat_loop`] catches the loop variant; this probe
//! catches the recursive variant.
//!
//! OSS source: ruff `PERF402` family + classic CS "concat in
//! recursion" perf trap.
//!
//! Phase-12 source-byte heuristic: scan `.py` / `.js` / `.ts` files
//! (skip tests + rule-pack source). For each function `def` /
//! `function` / arrow body, look for both signals on the same body:
//! (1) `<name> = <name> + ...` or `<name> += ...` where the LHS is
//! likely a string buffer (`s`, `out`, `acc`, `result`, etc.); (2) a
//! self-call `<fn_name>(...)`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_js_or_ts_path, is_test_file_path_py, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 perf rule `cc.perf.string_concat_in_recursion`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StringConcatInRecursionRule;

const STRING_BUFFER_NAMES: &[&str] = &[
    "s", "out", "buf", "text", "result", "acc", "msg", "html", "json", "output",
];

impl Rule for StringConcatInRecursionRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.string_concat_in_recursion"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "string concat inside a self-recursive function — quadratic work"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            let is_py = path.extension() == Some("py");
            let is_js = is_js_or_ts_path(&path);
            if !is_py && !is_js {
                continue;
            }
            if looks_like_rule_pack_source(&path) {
                continue;
            }
            if is_py && is_test_file_path_py(&path) {
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
        let Some(fn_name) = parse_fn_header(line) else {
            continue;
        };
        let body_end = body_end_index(&lines, idx);
        let body = &lines[idx + 1..body_end];
        if body_has_concat_and_recursion(body, &fn_name) {
            out.push(emit(path.clone(), idx + 1, line, &fn_name));
        }
    }
}

const FN_PREFIXES: &[&str] = &["def ", "async def ", "function ", "async function "];

fn parse_fn_header(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = FN_PREFIXES.iter().find_map(|p| trimmed.strip_prefix(p))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Stop at the first non-blank line whose indent is `<= def_indent`,
/// or at the next `function`/`def` header.
fn body_end_index(lines: &[&str], def_idx: usize) -> usize {
    let def_indent = lines[def_idx]
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    for (offset, line) in lines.iter().enumerate().skip(def_idx + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .count();
        if indent <= def_indent {
            return offset;
        }
    }
    lines.len()
}

/// True iff body contains both a string-concat assignment AND a
/// self-call to `fn_name`.
fn body_has_concat_and_recursion(body: &[&str], fn_name: &str) -> bool {
    let mut concat = false;
    let mut recursive = false;
    for line in body {
        if !concat && line_is_string_concat(line) {
            concat = true;
        }
        if !recursive && line_calls_self(line, fn_name) {
            recursive = true;
        }
        if concat && recursive {
            return true;
        }
    }
    false
}

fn line_is_string_concat(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return false;
    }
    if let Some((lhs, rhs)) = split_simple_assign(trimmed) {
        let lhs_clean = lhs.trim();
        if !is_likely_string_name(lhs_clean) {
            return false;
        }
        // s = s + ...
        if rhs.trim_start().starts_with(&format!("{lhs_clean} +"))
            || rhs.trim_start().starts_with(&format!("{lhs_clean}+"))
        {
            return true;
        }
    }
    if let Some((lhs, _)) = split_compound_assign(trimmed, " += ") {
        return is_likely_string_name(lhs.trim());
    }
    false
}

fn split_simple_assign(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(" = ")?;
    Some((&s[..idx], &s[idx + 3..]))
}

fn split_compound_assign<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let idx = s.find(op)?;
    Some((&s[..idx], &s[idx + op.len()..]))
}

fn is_likely_string_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    STRING_BUFFER_NAMES.iter().any(|hint| {
        lower == *hint
            || lower.contains(&format!("_{hint}"))
            || lower.starts_with(&format!("{hint}_"))
    })
}

fn line_calls_self(line: &str, fn_name: &str) -> bool {
    let needle = format!("{fn_name}(");
    let Some(idx) = line.find(&needle) else {
        return false;
    };
    if idx == 0 {
        return true;
    }
    let prev = line.as_bytes()[idx - 1];
    !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, fn_name: &str) -> Finding {
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
        rule_id: "cc.perf.string_concat_in_recursion",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{fn_name}` concatenates a string and recurses into itself"),
        explanation: format!(
            "Strings are immutable in Python and JS. Each `acc = acc + \
             ...` (or `acc += ...`) inside `{fn_name}` allocates a \
             fresh string equal to the full accumulated length. \
             Combined with the self-call this drives total work to \
             O(N^2) where N is the recursion depth — fine for tiny \
             trees, catastrophic past a few hundred nodes."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Push fragments into a list (Python: `parts = []; \
             parts.append(...)`; JS: `parts.push(...)`) and join \
             once at the top level: `\"\".join(parts)` / \
             `parts.join(\"\")`. Total work drops to O(N)."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
