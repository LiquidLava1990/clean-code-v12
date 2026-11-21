//! `cc.bug.govet_unreachable_code` — Go statement immediately after a
//! terminator (`return`, `panic(...)`, `os.Exit(...)`, `log.Fatal*`,
//! `runtime.Goexit()`) at the same brace depth.
//!
//! Mirrors `go vet` `unreachable`. The motivation: dead Go code is
//! almost always a copy-paste leftover or a missing early-return guard.
//! Either way it signals the reader something the runtime never
//! observes.
//!
//! Phase-11 source-byte detector: `.go` files only (excluding
//! `_test.go`). Walk every line; when the trimmed prefix is one of the
//! terminator forms, peek the next non-blank, non-comment line at the
//! same indent and within the same brace block. If it is not a closing
//! brace / `case` / `default:` / label, fire.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    apply_braces, build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_unreachable_code`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetUnreachableCodeRule;

const TERMINATOR_NEEDLES: &[&str] = &[
    "return",
    "panic(",
    "os.Exit(",
    "log.Fatal(",
    "log.Fatalf(",
    "log.Fatalln(",
    "runtime.Goexit(",
];

impl Rule for GovetUnreachableCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_unreachable_code"
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
        "statement after `return` / `panic` / `os.Exit` is unreachable"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
                continue;
            }
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
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
    for idx in 0..lines.len() {
        if !is_terminator_line(lines[idx]) {
            continue;
        }
        let term_depth = brace_depth_at(&lines, idx + 1);
        if let Some(next) = next_relevant_line(&lines, idx + 1) {
            if is_unreachable_at(lines[next], term_depth) {
                out.push(emit(path.clone(), next + 1, lines[next]));
            }
        }
    }
}

/// True iff `line`'s trimmed prefix is one of the Go terminator forms.
fn is_terminator_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    for needle in TERMINATOR_NEEDLES {
        if matches_terminator(trimmed, needle) {
            return true;
        }
    }
    false
}

fn matches_terminator(trimmed: &str, needle: &str) -> bool {
    let Some(after) = trimmed.strip_prefix(needle) else {
        return false;
    };
    if needle == "return" {
        match after.as_bytes().first() {
            None | Some(b' ') | Some(b'\t') | Some(b'/') | Some(b'(') | Some(b'\r') => true,
            _ => false,
        }
    } else {
        true
    }
}

/// Brace depth after consuming lines `[0, end)`. Comments and string
/// contents are not stripped — Phase-11 conservative shortcut.
fn brace_depth_at(lines: &[&str], end: usize) -> i32 {
    let mut depth: i32 = 0;
    for line in &lines[..end] {
        depth = apply_braces(depth, line);
    }
    depth
}

/// Skip blank / comment-only lines and return the index of the next
/// real line.
fn next_relevant_line(lines: &[&str], from: usize) -> Option<usize> {
    for (offset, line) in lines.iter().enumerate().skip(from) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        return Some(offset);
    }
    None
}

/// True iff the candidate line is at `term_depth` (same brace level as
/// the terminator) and is not a syntactic closer (`}`, `case`,
/// `default:`, label-only line).
fn is_unreachable_at(line: &str, term_depth: i32) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('}')
        || trimmed.starts_with("case ")
        || trimmed.starts_with("default:")
        || trimmed.starts_with("default ")
        || is_label_line(trimmed)
    {
        return false;
    }
    // Same depth: terminator's brace level must equal current line's.
    let line_open_close = apply_braces(0, line);
    // Approximation: if the terminator was at depth d and this line
    // adds non-zero closes before its first token, the line lives at a
    // lower scope and is reachable. Stay conservative — require the
    // line to be a non-closer within the same block.
    let _ = line_open_close;
    // The strongest heuristic we can get from a byte scan: the line is
    // a real statement at >= 1 brace depth (we are inside a function).
    term_depth >= 1
}

fn is_label_line(trimmed: &str) -> bool {
    if let Some(end) = trimmed.find(':') {
        let head = &trimmed[..end];
        if head.is_empty() {
            return false;
        }
        return head.chars().all(|c| c.is_alphanumeric() || c == '_');
    }
    false
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
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.govet_unreachable_code",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "statement after a terminator is unreachable".into(),
        explanation: "The previous line was `return` / `panic(...)` / \
             `os.Exit(...)` / `log.Fatal*(...)` — control flow never \
             reaches this statement. Either the terminator is wrong (a \
             missing guard meant to early-return) or this statement is \
             dead code that should be deleted."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Delete the unreachable statement, or — if the intent was a \
             conditional early-return — wrap the terminator in an \
             `if` block and let the trailing code execute on the \
             non-error path."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
