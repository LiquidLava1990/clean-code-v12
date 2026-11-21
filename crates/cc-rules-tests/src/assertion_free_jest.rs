//! `cc.test.assertion_free_jest` — JS / TS Jest / Mocha test body with
//! no assertion call.
//!
//! Distinct from the language-agnostic `cc.test.assertion_free` probe,
//! which relies on the frontend to lift `test()` / `it()` blocks into
//! [`cc_cpg::NodeKind::Function`] nodes. The Phase-8 TypeScript
//! frontend lifts the *callback* but not always the framework-style
//! `test('name', () => { ... })` wrapper itself, so the existing probe
//! misses Jest tests when the frontend stamps the body as a
//! [`cc_cpg::NodeKind::Lambda`].
//!
//! This probe is a source-byte safety net: scan every JS / TS file
//! whose path looks like a test file, find each `test(` / `it(`
//! header, slice the body to the matching closing brace, and assert
//! it contains at least one of `expect(`, `assert.`, or `chai.`.
//!
//! OSS source: `eslint-plugin-jest`'s `expect-expect` rule.
//!
//! Confidence 0.9 — a JS test file with a `test('name', …)` block
//! and no `expect` / `assert` / `chai` is virtually always a real
//! issue.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, is_test_file_path, TestsFindingBlueprint};

/// Family-8 probe R-ASSERTION-FREE-JEST.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssertionFreeJestRule;

const SUPPORTED_EXTS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];

/// Substrings any of which counts as an assertion call.
const ASSERTION_NEEDLES: &[&str] = &[
    "expect(",
    "assert(",
    "assert.",
    "chai.",
    ".should(",
    ".should.",
    ".to.equal",
    ".toBe(",
    ".toEqual(",
    ".toMatch(",
    ".toThrow",
    ".toHaveBeenCalled",
];

/// Test-block prefixes we recognise as Jest / Mocha headers.
const TEST_HEADER_PREFIXES: &[&str] = &[
    "test(",
    "it(",
    "test.only(",
    "it.only(",
    "test.skip(",
    "it.skip(",
    "test.each(",
    "it.each(",
];

impl Rule for AssertionFreeJestRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.assertion_free_jest"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Jest / Mocha test body has no assertion call"
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
            if !is_test_file_path(&path) {
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
    for header in find_test_headers(text) {
        let Some(body) = extract_callback_body(text, header.body_start) else {
            continue;
        };
        if body_has_assertion(body) {
            continue;
        }
        out.push(emit(path.clone(), header.line, header.title, body));
    }
}

#[derive(Debug)]
struct Header<'a> {
    line: usize,
    title: &'a str,
    body_start: usize,
}

fn find_test_headers(text: &str) -> Vec<Header<'_>> {
    let mut out = Vec::new();
    for prefix in TEST_HEADER_PREFIXES {
        let mut search_from = 0;
        while let Some(rel) = text[search_from..].find(prefix) {
            let absolute = search_from + rel;
            if !is_call_start_token(text, absolute) {
                search_from = absolute + prefix.len();
                continue;
            }
            if let Some(header) = parse_header(text, absolute, prefix) {
                out.push(header);
            }
            search_from = absolute + prefix.len();
        }
    }
    out
}

/// True iff the byte before `idx` is whitespace / start-of-line / open
/// punctuation — i.e. `test(` is a free-standing call, not the tail of
/// `nestest(`.
fn is_call_start_token(text: &str, idx: usize) -> bool {
    let prev = idx
        .checked_sub(1)
        .and_then(|i| text.as_bytes().get(i).copied());
    match prev {
        None => true,
        Some(b) => !(b.is_ascii_alphanumeric() || b == b'_' || b == b'$'),
    }
}

fn parse_header<'a>(text: &'a str, start: usize, prefix: &str) -> Option<Header<'a>> {
    let after_open = start + prefix.len();
    let after = &text[after_open..];
    let title_open = after.find(['"', '\'', '`'])?;
    let quote = after.as_bytes()[title_open];
    let title_after = title_open + 1;
    let close = title_after + after[title_after..].find(quote as char)?;
    let title = &after[title_after..close];
    let comma = close + after[close..].find(',')?;
    let body_start = after_open + comma + 1;
    let line = 1 + text[..start].bytes().filter(|b| *b == b'\n').count();
    Some(Header {
        line,
        title,
        body_start,
    })
}

/// Slice from the first `{` after `body_start` to the matching close.
fn extract_callback_body(text: &str, body_start: usize) -> Option<&str> {
    let rest = text.get(body_start..)?;
    let open = rest.find('{')?;
    let body_text = &rest[open + 1..];
    let end = matching_brace_end(body_text)?;
    Some(&body_text[..end])
}

/// Mutable cursor state for [`matching_brace_end`] — keeps the loop
/// body flat by giving the helpers a single object to update.
struct BraceScan {
    depth: i32,
    in_str: Option<char>,
    prev: char,
}

fn matching_brace_end(s: &str) -> Option<usize> {
    let mut state = BraceScan {
        depth: 1,
        in_str: None,
        prev: ' ',
    };
    for (idx, c) in s.char_indices() {
        if state.in_str.is_some() {
            consume_string_literal(&mut state, c);
            state.prev = c;
            continue;
        }
        if let Some(closed_at) = update_brace_depth(&mut state, idx, c) {
            return Some(closed_at);
        }
        state.prev = c;
    }
    None
}

/// Inside a string / template / regex literal: clear `in_str` only when
/// we hit an un-escaped matching quote. Templates and regexes share the
/// rule because the probe only needs brace balance, not literal type.
fn consume_string_literal(state: &mut BraceScan, c: char) {
    let Some(quote) = state.in_str else {
        return;
    };
    if c == quote && state.prev != '\\' {
        state.in_str = None;
    }
}

/// Outside a literal: enter a literal on quote, push/pop depth on
/// braces, and signal completion when the matching close appears.
fn update_brace_depth(state: &mut BraceScan, idx: usize, c: char) -> Option<usize> {
    if is_string_quote(c) {
        state.in_str = Some(c);
        return None;
    }
    if c == '{' {
        state.depth += 1;
        return None;
    }
    if c == '}' {
        state.depth -= 1;
        if state.depth == 0 {
            return Some(idx);
        }
    }
    None
}

fn is_string_quote(c: char) -> bool {
    matches!(c, '"' | '\'' | '`')
}

fn body_has_assertion(body: &str) -> bool {
    ASSERTION_NEEDLES.iter().any(|needle| body.contains(needle))
}

fn emit(path: Utf8PathBuf, line_no: usize, title: &str, body: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(title.to_owned()),
    };
    let snippet: String = body.trim().chars().take(180).collect();
    build_finding(TestsFindingBlueprint {
        rule_id: "cc.test.assertion_free_jest",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("Jest / Mocha test `{title}` has no assertion"),
        explanation: format!(
            "The body of `test('{title}', ...)` (or `it('{title}', ...)`) \
             contains no `expect(...)`, `assert.*`, or `chai.*` call. The \
             test runs but cannot fail — it provides regression coverage \
             in name only. eslint-plugin-jest flags this as `expect-expect`."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add at least one assertion that pins the behaviour under \
             test (`expect(value).toBe(...)`, `assert.equal(...)`, …). \
             If the test is intentionally a smoke harness, rename it so \
             the runner does not pick it up."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
