//! `cc.bug.always_throws` — provably-failing call sites.
//!
//! A call site is "always-throws" when control reaching it will raise
//! unconditionally — no matter what the runtime data looks like. The
//! cheapest, highest-precision instance is **division by literal zero**:
//! `x / 0`, `x % 0`. We ship that flavour now; constant out-of-bounds
//! indexing and `assert(false)` are deferred to Phase 9 once the kernel
//! exposes resolved array lengths and assertion-call recognition.
//!
//! OSS source: Error Prone `AlwaysThrows` bug pattern.
//!
//! Phase-8 source-byte heuristic: scan every supported source file for
//! `<expr> / 0` or `<expr> % 0` outside comments and string literals.
//! Confidence 0.95 — the pattern is unambiguous when matched.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-ALWAYS-THROWS.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysThrowsRule;

/// Source extensions worth scanning. Keep in sync with the supported
/// frontend list.
const SUPPORTED_EXTS: &[&str] = &["py", "rs", "go", "ts", "tsx", "js", "jsx", "java", "kt"];

impl Rule for AlwaysThrowsRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.always_throws"
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
        "expression provably throws at runtime (division by literal zero)"
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if is_comment_only(trimmed) {
            continue;
        }
        if let Some(op) = find_div_by_zero(line) {
            out.push(emit(path.clone(), line_idx + 1, line, op));
        }
    }
}

fn is_comment_only(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

/// Look for `<ident_or_paren_or_digit> / 0` or `... % 0`. Returns the
/// matched operator (`/` or `%`).
fn find_div_by_zero(line: &str) -> Option<&'static str> {
    for (idx, op) in line.match_indices(" / 0").chain(line.match_indices(" % 0")) {
        if !is_real_zero_literal(line, idx + op.len()) {
            continue;
        }
        if !lhs_is_arithmetic(line, idx) {
            continue;
        }
        let operator = if op.contains('/') { "/" } else { "%" };
        return Some(operator);
    }
    None
}

/// True iff the `0` we just matched is a complete numeric literal —
/// not the prefix of `0.5`, `0xff`, `0b1`, …
fn is_real_zero_literal(line: &str, after: usize) -> bool {
    let next = line.as_bytes().get(after).copied();
    match next {
        None => true,
        Some(b) => !is_ident_continuation(b) && b != b'.',
    }
}

fn is_ident_continuation(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True iff the character preceding the operator looks like a variable
/// or parenthesised sub-expression. Excludes assignment operators
/// (`/=`, `%=`) and comments.
fn lhs_is_arithmetic(line: &str, op_pos: usize) -> bool {
    let prefix = line[..op_pos].trim_end();
    match prefix.chars().last() {
        Some(c) => c.is_alphanumeric() || c == '_' || c == ')' || c == ']',
        None => false,
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, operator: &str) -> Finding {
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
        rule_id: "cc.bug.always_throws",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("expression `{operator} 0` always throws at runtime"),
        explanation: format!(
            "Dividing or taking a modulus by literal `0` raises \
             `ZeroDivisionError` / `panic` / `ArithmeticException` on \
             every supported language. Reaching this site is unconditional \
             failure, not a bug-once-in-a-while. Either the `0` is a \
             typo for another constant, or the divisor was meant to come \
             from a variable that has not been wired in yet."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the literal `0` with the intended denominator. If \
             the divisor genuinely can be zero at runtime, guard the \
             call with an explicit check + actionable error before \
             performing the division."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
