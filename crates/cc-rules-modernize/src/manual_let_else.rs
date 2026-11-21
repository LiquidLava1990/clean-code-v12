//! `cc.modernize.manual_let_else` — `let x = match y { Some(v) => v,
//! None => return };` superseded by Rust 1.65 `let ... else`.
//!
//! Canonical pattern:
//! ```text
//! let user = match find_user(id) {
//!     Some(u) => u,
//!     None => return Err(MissingUser),
//! };
//! ```
//! Rust 1.65 introduced `let Some(user) = find_user(id) else {
//! return Err(MissingUser); };` which expresses the same control flow
//! in two lines, with one binding name, one `match` arm to read.
//!
//! OSS source: clippy `manual_let_else`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for the literal
//! pair (a) a line containing `let <name> = match` and (b) within a
//! small downward window two arms of the form `Some(<inner>) =>
//! <inner>,` and `None =>` followed by a divergent expression
//! (`return`, `panic!(`, `continue`, `break`, `process::exit(`).
//! Skip test files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.85.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.manual_let_else`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ManualLetElseRule;

const SEARCH_WINDOW: usize = 5;
const DIVERGENT_TOKENS: &[&str] = &[
    "return",
    "panic!(",
    "continue",
    "break",
    "process::exit(",
    "std::process::exit(",
    "todo!(",
    "unreachable!(",
];

impl Rule for ManualLetElseRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.manual_let_else"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "`let x = match { Some(v) => v, None => return }` is now `let Some(x) = ... else { return }`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
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
        if !line_starts_let_match(line) {
            continue;
        }
        if !window_has_let_else_pattern(&lines, idx) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line));
    }
}

fn line_starts_let_match(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    let rest = match trimmed.strip_prefix("let ") {
        Some(r) => r.strip_prefix("mut ").unwrap_or(r),
        None => return false,
    };
    let Some(eq_idx) = rest.find('=') else {
        return false;
    };
    rest[eq_idx + 1..].trim_start().starts_with("match ")
}

/// Look at up to [`SEARCH_WINDOW`] lines after `start`. Require both
/// a `Some(<name>) => <name>,` arm and a `None => <divergent>` arm.
fn window_has_let_else_pattern(lines: &[&str], start: usize) -> bool {
    let end = (start + 1 + SEARCH_WINDOW).min(lines.len());
    let window = &lines[start + 1..end];
    let some_arm = window.iter().any(|l| has_some_self_arm(l));
    let none_arm = window.iter().any(|l| has_diverging_none_arm(l));
    some_arm && none_arm
}

fn has_some_self_arm(line: &str) -> bool {
    let t = line.trim();
    let Some(rest) = t.strip_prefix("Some(") else {
        return false;
    };
    let Some(end_paren) = rest.find(')') else {
        return false;
    };
    let inner = &rest[..end_paren];
    let after = &rest[end_paren + 1..].trim_start();
    let Some(after_arrow) = after.strip_prefix("=>") else {
        return false;
    };
    let body = after_arrow.trim();
    let body = body.trim_end_matches(',').trim();
    inner == body && !inner.is_empty()
}

fn has_diverging_none_arm(line: &str) -> bool {
    let t = line.trim();
    let Some(rest) = t.strip_prefix("None") else {
        return false;
    };
    let after = rest.trim_start();
    let Some(after_arrow) = after.strip_prefix("=>") else {
        return false;
    };
    let body = after_arrow.trim();
    DIVERGENT_TOKENS.iter().any(|tok| body.starts_with(tok))
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
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.manual_let_else",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: "`let x = match y { Some(v) => v, None => return }` is now `let Some(x) = y else { return }`".into(),
        explanation:
            "Rust 1.65 introduced `let-else` so the early-exit case can \
             be expressed in a single statement: bind on success, \
             diverge on failure. The hand-rolled `let x = match { … }` \
             is two arms of `match` plus a stand-alone `let`, which \
             reads as control-flow-then-binding instead of \
             binding-with-fallback."
                .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the `let x = match y { Some(v) => v, None => \
             return … };` with `let Some(x) = y else { return … };`. \
             Same machine code, half the lines, and the binding name \
             appears exactly once."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
