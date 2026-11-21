//! `cc.test.testify_assertion_misuse` — testify `Equal` arg-order
//! reversal.
//!
//! testify's `assert.Equal(t, expected, actual)` and `require.Equal`
//! are routinely written as `assert.Equal(t, got, expected)` — the
//! arguments compare equal regardless, so the test still passes, but
//! the diagnostic message ("expected: <got>, actual: <expected>") is
//! reversed and the failure mode is impossible to read.
//!
//! OSS source: golangci-lint `testifylint` (rule `expected-actual`).
//!
//! Phase-8 source-byte heuristic (`.go` only): scan for `.Equal(t,
//! <arg2>, <arg3>)`. Without symbol info we cannot prove which side
//! is the constant; we ship a *low-precision* shadow that fires when
//! `arg2` is a variable identifier and `arg3` is a literal. Whatever
//! the convention, that pair is wrong — testify's convention puts the
//! literal in `arg2`.
//!
//! Confidence 0.75 — clearly marked low-precision. Documented in the
//! rule pack so reviewers can suppress without ratchet drift.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, TestsFindingBlueprint};

/// Family-8 probe R-TESTIFY-ASSERTION-MISUSE.
#[derive(Debug, Default, Clone, Copy)]
pub struct TestifyAssertionMisuseRule;

/// Methods we scan — testify's "expected-then-actual" family.
const EXPECTED_FIRST_METHODS: &[&str] = &[
    ".Equal(t, ",
    ".EqualValues(t, ",
    ".NotEqual(t, ",
    ".Exactly(t, ",
];

impl Rule for TestifyAssertionMisuseRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.testify_assertion_misuse"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "testify Equal-style call has expected/actual reversed (low precision)"
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(method) = find_misuse(line) {
            out.push(emit(path.clone(), line_idx + 1, line, method));
        }
    }
}

fn find_misuse(line: &str) -> Option<&'static str> {
    for method in EXPECTED_FIRST_METHODS {
        let Some(after_call) = call_args_after(line, method) else {
            continue;
        };
        let (arg2, arg3) = split_two_args(after_call)?;
        if classify_arg(arg2) != ArgKind::Variable {
            continue;
        }
        if classify_arg(arg3) != ArgKind::Literal {
            continue;
        }
        return Some(method);
    }
    None
}

fn call_args_after<'a>(line: &'a str, method: &str) -> Option<&'a str> {
    let idx = line.find(method)?;
    let after = &line[idx + method.len()..];
    let close = balanced_paren_end(after)?;
    Some(&after[..close])
}

/// Find the offset of the matching close paren given that the cursor
/// sits after the opening paren has already been consumed.
fn balanced_paren_end(s: &str) -> Option<usize> {
    let mut depth: i32 = 1;
    for (idx, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split the args-tail into (arg2, arg3) — the two args after the `t,`
/// prefix that is already consumed by the method needle.
fn split_two_args(args: &str) -> Option<(&str, &str)> {
    let comma = top_level_comma(args)?;
    let arg2 = args[..comma].trim();
    let rest = args[comma + 1..].trim();
    let arg3_end = top_level_comma(rest).unwrap_or(rest.len());
    let arg3 = rest[..arg3_end].trim();
    if arg2.is_empty() || arg3.is_empty() {
        None
    } else {
        Some((arg2, arg3))
    }
}

/// Index of the first top-level `,` (depth 0 across `()`, `[]`, and
/// quoted string literals).
fn top_level_comma(s: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut in_str: Option<char> = None;
    let mut prev: char = ' ';
    for (idx, c) in s.char_indices() {
        if let Some(quote) = in_str {
            if c == quote && prev != '\\' {
                in_str = None;
            }
        } else {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '"' | '\'' | '`' => in_str = Some(c),
                ',' if depth == 0 => return Some(idx),
                _ => {}
            }
        }
        prev = c;
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum ArgKind {
    Literal,
    Variable,
    Other,
}

fn classify_arg(arg: &str) -> ArgKind {
    if arg.is_empty() {
        return ArgKind::Other;
    }
    if is_string_literal(arg) || is_numeric_literal(arg) || is_bool_literal(arg) {
        return ArgKind::Literal;
    }
    if is_simple_identifier_or_field(arg) {
        return ArgKind::Variable;
    }
    ArgKind::Other
}

fn is_string_literal(arg: &str) -> bool {
    let bytes = arg.as_bytes();
    matches!(bytes.first(), Some(b'"' | b'\'' | b'`'))
}

fn is_numeric_literal(arg: &str) -> bool {
    let bytes = arg.as_bytes();
    matches!(bytes.first(), Some(b) if b.is_ascii_digit() || *b == b'-')
        && arg
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'x' || c == 'e')
}

fn is_bool_literal(arg: &str) -> bool {
    matches!(arg, "true" | "false" | "nil")
}

fn is_simple_identifier_or_field(arg: &str) -> bool {
    arg.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && arg
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, method: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TestsFindingBlueprint {
        rule_id: "cc.test.testify_assertion_misuse",
        severity: Severity::Required,
        confidence: Confidence::new(0.75),
        location,
        headline: format!(
            "testify `{}` looks like `(t, got, expected)` — testify wants `(t, expected, got)`",
            method.trim_start_matches('.').trim_end_matches("(t, ")
        ),
        explanation: "testify's `Equal` family takes `(t, expected, actual)`. \
             Reversing the order does not flip the boolean result so \
             the test still passes, but the failure diagnostic prints \
             `expected: <actual>, actual: <expected>` — completely \
             unreadable. This probe is intentionally low-precision \
             (no symbol info): it fires when arg-2 is a variable and \
             arg-3 is a literal, which is the most common reversal."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Swap the arguments so the expected (literal / constant) \
             comes first: `assert.Equal(t, expectedValue, gotValue)`. \
             Suppress with `// nolint:testifylint` if the convention \
             genuinely flipped in this codebase."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
