//! `cc.bug.govet_printf_format` — Go-specific printf placeholder /
//! argument count mismatch focused on `%v`, `%+v`, `%T`, `%q` verbs
//! that the multi-language [`crate::format_string_drift`] probe doesn't
//! cover at the Go-only verb resolution.
//!
//! Canonical bug:
//! ```go
//! fmt.Printf("%s %d", x)              // 2 verbs, 1 arg
//! fmt.Errorf("got %T (%+v)", payload) // 2 verbs, 1 arg
//! log.Printf("%q", a, b)              // 1 verb, 2 args
//! ```
//! `go vet -printf` catches these at compile time. We can match the
//! same shape from source bytes for `.go` files.
//!
//! OSS source: `go vet -printf` (golang.org/x/tools/go/analysis/passes/printf).
//!
//! Phase-12 source-byte heuristic: `.go` files only (skip `_test.go`).
//! Find calls to canonical Go printf families on a single line:
//! `fmt.Printf` / `fmt.Sprintf` / `fmt.Fprintf` / `fmt.Errorf` /
//! `log.Printf` / `t.Logf` / `t.Errorf`. Parse the literal first
//! argument. Count Go-specific verbs (`%v`, `%+v`, `%T`, `%q`,
//! `%s`, `%d`, `%w`, `%x`, `%f`). Count comma-separated args after
//! the format string. Mismatch -> emit.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_printf_format`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetPrintfFormatRule;

const PRINTF_FAMILIES: &[&str] = &[
    "fmt.Printf",
    "fmt.Sprintf",
    "fmt.Fprintf",
    "fmt.Errorf",
    "log.Printf",
    "log.Fatalf",
    "log.Panicf",
    "t.Logf",
    "t.Errorf",
    "t.Fatalf",
];

impl Rule for GovetPrintfFormatRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_printf_format"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Go printf placeholder count != argument count"
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
    for (idx, line) in text.lines().enumerate() {
        let Some(callee) = find_printf_family(line) else {
            continue;
        };
        let Some((verbs, args)) = parse_printf_call(line, callee) else {
            continue;
        };
        if verbs != args {
            out.push(emit(EmitInputs {
                path: path.clone(),
                line_no: idx + 1,
                line,
                callee,
                verbs,
                args,
            }));
        }
    }
}

/// Inputs for [`emit`] — fields beat a 6-arg positional list.
struct EmitInputs<'a> {
    path: Utf8PathBuf,
    line_no: usize,
    line: &'a str,
    callee: &'a str,
    verbs: usize,
    args: usize,
}

fn find_printf_family(line: &str) -> Option<&'static str> {
    PRINTF_FAMILIES
        .iter()
        .find(|fam| line.contains(&format!("{fam}(")))
        .copied()
}

/// Parse `<callee>("<format>", a, b, ...)` on a single line. Returns
/// `(verb_count, arg_count)`. Returns `None` when the format literal
/// or the argument list cannot be cleanly extracted (e.g. multi-line
/// call, dynamic format string).
fn parse_printf_call(line: &str, callee: &str) -> Option<(usize, usize)> {
    let needle = format!("{callee}(");
    let abs = line.find(&needle)?;
    let after_open = abs + needle.len();
    let rest = &line[after_open..];
    // First arg must be a string literal "..." with no escaped quotes
    // for our heuristic to apply.
    let rest = rest.trim_start();
    let lit_rest = rest.strip_prefix('"')?;
    let lit_end = find_unescaped_quote(lit_rest)?;
    let format = &lit_rest[..lit_end];
    let after_lit = &lit_rest[lit_end + 1..];
    let after_lit = after_lit.trim_start();
    let args_str = after_lit.strip_prefix(',').map(str::trim_start);
    let arg_count = match args_str {
        Some(s) => count_top_level_args(s),
        None => 0,
    };
    Some((count_verbs(format), arg_count))
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Count Go printf verbs: `%v`, `%+v`, `%T`, `%q`, `%s`, `%d`, `%w`,
/// `%x`, `%X`, `%f`, `%g`, `%e`, `%b`, `%o`, `%c`, `%p`, `%U`, `%t`.
/// Treat `%%` as a literal percent (no verb). Width/precision flags
/// (`%5.2f`, `%-10s`, `%+v`) are tolerated.
fn count_verbs(format: &str) -> usize {
    let bytes = format.as_bytes();
    let mut i = 0;
    let mut count = 0;
    while i < bytes.len() {
        match try_consume_verb(bytes, i) {
            VerbStep::Verb(next) => {
                count += 1;
                i = next;
            }
            VerbStep::Skip(next) => i = next,
        }
    }
    count
}

#[derive(Debug)]
enum VerbStep {
    Verb(usize),
    Skip(usize),
}

/// Inspect `bytes[i]`. If it begins a verb sequence, return the
/// post-verb index; otherwise return the next inspection index.
fn try_consume_verb(bytes: &[u8], i: usize) -> VerbStep {
    if bytes[i] != b'%' {
        return VerbStep::Skip(i + 1);
    }
    let next = bytes.get(i + 1).copied();
    if next == Some(b'%') {
        return VerbStep::Skip(i + 2);
    }
    if next.is_none() {
        return VerbStep::Skip(bytes.len());
    }
    let after_flags = skip_flags(bytes, i + 1);
    let after_width = skip_digits(bytes, after_flags);
    let after_prec = skip_precision(bytes, after_width);
    if let Some(b) = bytes.get(after_prec).copied() {
        if is_verb_byte(b) {
            return VerbStep::Verb(after_prec + 1);
        }
    }
    VerbStep::Skip(i + 1)
}

fn skip_flags(bytes: &[u8], mut j: usize) -> usize {
    while j < bytes.len() && b"+-# 0".contains(&bytes[j]) {
        j += 1;
    }
    j
}

fn skip_digits(bytes: &[u8], mut j: usize) -> usize {
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    j
}

fn skip_precision(bytes: &[u8], j: usize) -> usize {
    if bytes.get(j).copied() == Some(b'.') {
        skip_digits(bytes, j + 1)
    } else {
        j
    }
}

fn is_verb_byte(b: u8) -> bool {
    matches!(
        b,
        b'v' | b'T'
            | b'q'
            | b's'
            | b'd'
            | b'w'
            | b'x'
            | b'X'
            | b'f'
            | b'g'
            | b'e'
            | b'b'
            | b'o'
            | b'c'
            | b'p'
            | b'U'
            | b't'
    )
}

/// Count comma-separated top-level arguments in `s` up to the matching
/// close paren. Tracks paren / bracket / brace / quote depth so commas
/// inside nested calls or composite literals are not counted.
fn count_top_level_args(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut count: usize = 0;
    let mut saw_token = false;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(q) = quote {
            i = advance_in_quote(bytes, i, q, &mut quote);
            continue;
        }
        let b = bytes[i];
        if is_close_paren(b) && depth == 0 {
            if saw_token {
                count += 1;
            }
            return count;
        }
        i += 1;
        update_state(b, &mut depth, &mut quote, &mut count, &mut saw_token);
    }
    if saw_token {
        count + 1
    } else {
        count
    }
}

fn advance_in_quote(bytes: &[u8], i: usize, q: u8, quote: &mut Option<u8>) -> usize {
    if bytes[i] == b'\\' {
        return i + 2;
    }
    if bytes[i] == q {
        *quote = None;
    }
    i + 1
}

const fn is_close_paren(b: u8) -> bool {
    matches!(b, b')' | b']' | b'}')
}

fn update_state(
    b: u8,
    depth: &mut i32,
    quote: &mut Option<u8>,
    count: &mut usize,
    saw_token: &mut bool,
) {
    match b {
        b'"' | b'\'' | b'`' => {
            *quote = Some(b);
            *saw_token = true;
        }
        b'(' | b'[' | b'{' => *depth += 1,
        b')' | b']' | b'}' => *depth -= 1,
        b',' if *depth == 0 => {
            *count += 1;
            *saw_token = false;
        }
        b' ' | b'\t' => {}
        _ => *saw_token = true,
    }
}

fn emit(input: EmitInputs<'_>) -> Finding {
    let EmitInputs {
        path,
        line_no,
        line,
        callee,
        verbs,
        args,
    } = input;
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
        rule_id: "cc.bug.govet_printf_format",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{callee}` format has {verbs} verb(s) but received {args} arg(s)"),
        explanation: format!(
            "Go's printf family expects exactly one value per `%`-verb \
             (excluding `%%`). This call has {verbs} verb(s) but supplies \
             {args} value(s). At runtime extra args are silently dropped \
             and missing args render as `%!v(MISSING)` — a footgun the \
             compiler can't catch but `go vet -printf` does. The same \
             check applies to `%+v` (struct-pretty), `%T` (type), and \
             `%q` (Go-quoted) verbs."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Run `go vet ./...` and align the verb count with the \
             argument list. Common fixes: drop the stray arg, add the \
             missing value, or escape an intended `%` as `%%`."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
