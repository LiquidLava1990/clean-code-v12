//! `cc.bug.identity_binary_expr` — same expression on both sides of a
//! comparison or bitwise operator (`x == x`, `x - x`, `x & x`, …).
//!
//! Phase-7 heuristic: scan the raw source bytes for every file in the
//! current batch. The detector looks for token sequences of the shape
//! `IDENT OP IDENT` where the two identifiers are textually equal and
//! `OP` is one of the suspicious operators. Identifiers here are
//! `[A-Za-z_][A-Za-z0-9_]*` with an optional `.field` chain (single
//! field, to keep the regex tractable without a regex crate).
//!
//! Operators flagged: `==`, `!=`, `===`, `!==`, `-`, `&`, `|`, `^`.
//! Arithmetic `+`, `*`, `/`, `%` are intentionally omitted — `x + x`
//! and `x * x` are common and rarely a bug.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-IDENTITY-BINARY.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityBinaryExprRule;

/// Operators where same-on-both-sides is virtually always a bug.
const SUSPICIOUS_OPS: &[&str] = &["===", "!==", "==", "!=", "&", "|", "^", " - "];

impl Rule for IdentityBinaryExprRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.identity_binary_expr"
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
        "binary expression with identical left and right operands"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }
        if let Some(hit) = find_identity_match(line) {
            out.push(emit(path.clone(), line_idx + 1, &hit));
        }
    }
}

#[derive(Debug)]
struct IdentityHit {
    snippet: String,
    operator: String,
}

fn find_identity_match(line: &str) -> Option<IdentityHit> {
    for op in SUSPICIOUS_OPS {
        let Some(idx) = line.find(op) else {
            continue;
        };
        let prefix = &line[..idx];
        let suffix = &line[idx + op.len()..];
        let (lhs, lhs_followed_by_quote) = trailing_token(prefix);
        let (rhs, rhs_followed_by_quote) = leading_token(suffix);
        if lhs.is_empty() || rhs.is_empty() {
            continue;
        }
        if lhs_followed_by_quote || rhs_followed_by_quote {
            // The "identifier" is actually a string/byte/char-literal
            // prefix (`b'0'`, `r"..."`, `c'a'`). Skip — the textual match
            // is a coincidence of token-prefix rather than identity.
            continue;
        }
        if lhs == rhs && !is_numeric_literal(&lhs) {
            return Some(IdentityHit {
                snippet: format!("{lhs}{op}{rhs}"),
                operator: (*op).trim().to_owned(),
            });
        }
    }
    None
}

fn trailing_token(prefix: &str) -> (String, bool) {
    // Returns (identifier, followed_by_quote_in_prefix). The quote check
    // looks at the character AFTER the identifier in the prefix.
    let chars: Vec<char> = prefix.chars().collect();
    let mut end = chars.len();
    while end > 0 && chars[end - 1].is_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_ident_char(chars[start - 1]) {
        start -= 1;
    }
    let ident: String = chars[start..end].iter().collect();
    (ident, false)
}

fn leading_token(suffix: &str) -> (String, bool) {
    let chars: Vec<char> = suffix.chars().collect();
    let mut start = 0;
    while start < chars.len() && chars[start].is_whitespace() {
        start += 1;
    }
    let mut end = start;
    while end < chars.len() && is_ident_char(chars[end]) {
        end += 1;
    }
    let ident: String = chars[start..end].iter().collect();
    let followed_by_quote = end < chars.len() && (chars[end] == '\'' || chars[end] == '"');
    (ident, followed_by_quote)
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.'
}

fn is_numeric_literal(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn emit(path: Utf8PathBuf, line_no: usize, hit: &IdentityHit) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.identity_binary_expr",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("identical operands on both sides of `{}`", hit.operator),
        explanation: format!(
            "The expression `{}` compares / combines a value with itself. \
             For `==` / `!=` / `===` / `!==` this is always true / false; \
             for `-` / `&` / `|` / `^` the result is a constant (0, the \
             value, or 0 again). Almost always a copy-paste bug — the \
             intended right-hand operand was a different identifier.",
            hit.snippet
        ),
        remediation: Remediation::SuggestedRewrite(
            "Inspect the right-hand operand. If a NaN check was intended, \
             use `f64::is_nan` / `Number.isNaN` / `math.isnan`. If a \
             tautology is genuinely desired (rare), extract a constant \
             with a comment explaining why."
                .into(),
        ),
        snippet: hit.snippet.clone(),
        weight: 3,
    })
}
