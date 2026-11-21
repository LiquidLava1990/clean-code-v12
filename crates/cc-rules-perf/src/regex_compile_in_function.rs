//! `cc.perf.regex_compile_in_function` — Python function body that
//! calls `re.compile("...")` on a literal pattern.
//!
//! Canonical bug:
//! ```python
//! def is_email(s):
//!     pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
//!     return pattern.match(s) is not None
//! ```
//! Each call to `is_email` recompiles the regex, even though the
//! pattern is a constant literal. Hoist the `re.compile` to module
//! scope and the per-call cost drops to a single `match`. The wider
//! [`crate::regex_compile_in_loop`] catches this when the call is
//! also inside a loop; this probe catches the simpler "compiled once
//! per call" case.
//!
//! OSS source: ruff `PERF402` / common Python perf guides.
//!
//! Phase-12 source-byte heuristic: `.py` files only (skip tests +
//! rule-pack source). Find every `def <name>(` line, then within the
//! function body (indent-based) flag any `re.compile(...)` whose first
//! argument is a string / raw-string / byte-string literal.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path_py, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 perf rule `cc.perf.regex_compile_in_function`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegexCompileInFunctionRule;

impl Rule for RegexCompileInFunctionRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.regex_compile_in_function"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "`re.compile(\"...\")` called inside a function body — hoist to module scope"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if is_test_file_path_py(&path) || looks_like_rule_pack_source(&path) {
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
    let mut idx = 0;
    while idx < lines.len() {
        let Some(def_indent) = python_def_indent(lines[idx]) else {
            idx += 1;
            continue;
        };
        let body_end = body_end_index(&lines, idx, def_indent);
        for body_idx in idx + 1..body_end {
            let line = lines[body_idx];
            if line_has_re_compile_literal(line) {
                out.push(emit(path.clone(), body_idx + 1, line));
            }
        }
        idx = body_end.max(idx + 1);
    }
}

/// Return the indent column of `line` if it starts with `def ` or
/// `async def `, otherwise `None`.
fn python_def_indent(line: &str) -> Option<usize> {
    let indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    let trimmed = &line[indent..];
    if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
        Some(indent)
    } else {
        None
    }
}

/// Walk lines after the def header until the first non-blank line whose
/// indent is `<= def_indent`. Returns an exclusive end index.
fn body_end_index(lines: &[&str], def_idx: usize, def_indent: usize) -> usize {
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

/// True iff the line invokes `re.compile(...)` with a literal first
/// argument. Tolerates the call appearing as a sub-expression (e.g.
/// `pattern = re.compile(r"...")`).
fn line_has_re_compile_literal(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return false;
    }
    let Some(call_start) = line.find("re.compile(") else {
        return false;
    };
    let after = &line[call_start + "re.compile(".len()..];
    let after = after.trim_start();
    starts_with_string_literal(after)
}

fn starts_with_string_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        && matches!(
            bytes[i],
            b'r' | b'R' | b'b' | b'B' | b'f' | b'F' | b'u' | b'U'
        )
    {
        i += 1;
        if i - 0 > 2 {
            break;
        }
    }
    matches!(bytes.get(i).copied(), Some(b'"') | Some(b'\''))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
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
        rule_id: "cc.perf.regex_compile_in_function",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "`re.compile(\"...\")` re-runs on every function call".into(),
        explanation: "Compiling a regex is O(pattern-length) and not cached \
             unless the exact same string object is reused. A literal \
             pattern compiled inside a function body recompiles on \
             every call: the cost is paid by every caller forever, even \
             though the pattern is constant. Hoist the `re.compile` to \
             module scope (or the closure of an enclosing class) and \
             the function body shrinks to a single `match` / `search` \
             call."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move the `re.compile(\"...\")` to module-top-level: \
             `_PATTERN = re.compile(r\"...\")`. Reference `_PATTERN` \
             from the function. Same observable behaviour, one \
             compile instead of N."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
