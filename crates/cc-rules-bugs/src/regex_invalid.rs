//! `cc.bug.regex_invalid` — call to a regex compiler with a literal
//! pattern that fails the cheap structural validity heuristics:
//!
//! - unbalanced `[ ]` character class
//! - unbalanced `( )` group
//! - dangling `\` at end-of-pattern
//! - unmatched `}` after a `{n,m}` quantifier
//!
//! Detected callees: `regex::Regex::new`, `Regex::new`, `re.compile`,
//! `re.search`, `re.match`, `RegExp(...)`, `new RegExp(...)`,
//! `regexp.MustCompile`, `regexp.Compile`.
//!
//! Phase-7 conservative: only the literal first argument is checked.
//! Concatenated / formatted patterns flow through later phases.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-REGEX-INVALID.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegexInvalidRule;

const REGEX_CALLEES: &[&str] = &[
    "regex::Regex::new",
    "Regex::new",
    "re.compile",
    "re.search",
    "re.match",
    "re.fullmatch",
    "re.findall",
    "re.sub",
    "RegExp",
    "regexp.MustCompile",
    "regexp.Compile",
];

impl Rule for RegexInvalidRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.regex_invalid"
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
        "regex literal is structurally unparseable (unbalanced brackets / dangling backslash)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, call.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let callee = callee_text(ctx.batch, call);
    if !REGEX_CALLEES.iter().any(|n| callee.contains(n)) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let pattern = first_literal_child_value(ctx, call)?;
    let problem = validate_pattern(&pattern)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(emit(location, &callee, &pattern, problem))
}

fn first_literal_child_value(ctx: &RuleContext<'_>, call: NodeId) -> Option<String> {
    for child in ast_children(ctx.batch, call) {
        if node_kind(ctx.batch, child) == Some(NodeKind::Literal) {
            if let Some(value) = string_prop(ctx.batch, child, "value") {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum Problem {
    UnbalancedBracket,
    UnbalancedParen,
    DanglingBackslash,
    UnmatchedQuantifier,
}

impl Problem {
    const fn label(self) -> &'static str {
        match self {
            Self::UnbalancedBracket => "unbalanced `[`",
            Self::UnbalancedParen => "unbalanced `(`",
            Self::DanglingBackslash => "dangling `\\` at end",
            Self::UnmatchedQuantifier => "unmatched `{...}` quantifier",
        }
    }
}

fn validate_pattern(p: &str) -> Option<Problem> {
    if has_dangling_backslash(p) {
        return Some(Problem::DanglingBackslash);
    }
    if !brackets_balanced(p) {
        return Some(Problem::UnbalancedBracket);
    }
    if !parens_balanced(p) {
        return Some(Problem::UnbalancedParen);
    }
    if has_unmatched_quantifier(p) {
        return Some(Problem::UnmatchedQuantifier);
    }
    None
}

fn has_dangling_backslash(p: &str) -> bool {
    if !p.ends_with('\\') {
        return false;
    }
    // Check that the trailing backslash is not itself escaped.
    let trailing = p.bytes().rev().take_while(|b| *b == b'\\').count();
    trailing % 2 == 1
}

fn brackets_balanced(p: &str) -> bool {
    scan_pattern(p).bracket_depth == 0
}

fn parens_balanced(p: &str) -> bool {
    let report = scan_pattern(p);
    report.paren_depth == 0 && !report.paren_underflow
}

fn has_unmatched_quantifier(p: &str) -> bool {
    scan_pattern(p).bad_quantifier
}

/// Aggregate report from one walk of a regex literal.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RegexScanReport {
    /// Net `[` depth at end-of-string. Non-zero = unbalanced class.
    bracket_depth: i32,
    /// Net `(` depth at end-of-string. Non-zero = unbalanced group.
    paren_depth: i32,
    /// True if `)` ever appeared without a matching `(`.
    paren_underflow: bool,
    /// True if a `{` opened a quantifier that did not close cleanly.
    bad_quantifier: bool,
}

/// Walk `pattern` once and report all structural balance facts. Three
/// thin callers ([`brackets_balanced`] / [`parens_balanced`] /
/// [`has_unmatched_quantifier`]) project the slice they care about.
///
/// A single shared scanner removes the per-check duplication and keeps
/// each balance check at depth-1, since the loop body delegates to
/// helpers.
fn scan_pattern(pattern: &str) -> RegexScanReport {
    let mut report = RegexScanReport::default();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if consume_escape(c, &mut chars) {
            continue;
        }
        update_balance(c, &mut report);
        if c == '{' && !quantifier_well_formed(&mut chars) {
            report.bad_quantifier = true;
        }
    }
    report
}

/// Skip the next char when `c` is `\`. Returns true when an escape was
/// consumed so the caller can `continue`.
fn consume_escape(c: char, chars: &mut std::str::Chars<'_>) -> bool {
    if c != '\\' {
        return false;
    }
    let _ = chars.next();
    true
}

/// Update the running bracket / paren depths for `c`. Tracks
/// "are we inside a `[…]` class" implicitly via [`RegexScanReport`].
fn update_balance(c: char, report: &mut RegexScanReport) {
    match c {
        '[' => report.bracket_depth += 1,
        ']' if report.bracket_depth > 0 => report.bracket_depth -= 1,
        '(' if report.bracket_depth == 0 => report.paren_depth += 1,
        ')' if report.bracket_depth == 0 => {
            report.paren_depth -= 1;
            if report.paren_depth < 0 {
                report.paren_underflow = true;
            }
        }
        _ => {}
    }
}

/// Consume the body of a `{n,m}` quantifier from `chars` and verify it
/// closes with `}` and contains only digits / `,` / spaces. Returns
/// `false` when the quantifier is malformed or unterminated.
fn quantifier_well_formed(chars: &mut std::str::Chars<'_>) -> bool {
    for inner in chars.by_ref() {
        if inner == '}' {
            return true;
        }
        if !inner.is_ascii_digit() && inner != ',' && inner != ' ' {
            return false;
        }
    }
    false
}

fn emit(location: cc_finding::Location, callee: &str, pattern: &str, problem: Problem) -> Finding {
    let snippet: String = pattern.chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.regex_invalid",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{callee}` regex pattern has {} ", problem.label()),
        explanation: format!(
            "The regex pattern `\"{snippet}\"` fails a cheap structural \
             validity check: {}. Compilation will throw at runtime — \
             usually on the first call, sometimes only on a code path that \
             reaches the regex months later.",
            problem.label()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rebalance the pattern (close every `[`, `(`, escape literal \
             backslashes as `\\\\`, complete every `{n,m}` quantifier). If \
             the pattern is composed dynamically, validate with a unit test \
             that compiles all known concatenations."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
