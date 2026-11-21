//! `cc.complete.unsafe_block_no_safety_comment` — Rust `unsafe { ... }`
//! without a preceding `// SAFETY:` comment.
//!
//! Rust doctrine (see clippy `undocumented_unsafe_blocks`): every
//! `unsafe { ... }` block must be preceded by a comment beginning with
//! `// SAFETY:` (or `/// SAFETY:`) explaining the invariants the
//! compiler cannot check. The rationale becomes load-bearing when
//! someone refactors the surrounding code two years later.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for occurrences of
//! `unsafe {` that are not part of an `unsafe fn` / `unsafe trait` /
//! `unsafe impl` / `unsafe trait` declaration, then check the prior
//! non-blank line(s) for a `SAFETY:` marker. Confidence 0.95 — the
//! pattern is unambiguous in Rust.
//!
//! OSS source: clippy `undocumented_unsafe_blocks` lint, Rust API
//! Guidelines C-UNSAFE.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, looks_like_rule_pack_source, CompletenessFindingBlueprint};

/// Probe `cc.complete.unsafe_block_no_safety_comment`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsafeBlockNoSafetyCommentRule;

impl Rule for UnsafeBlockNoSafetyCommentRule {
    fn rule_id(&self) -> &'static str {
        "cc.complete.unsafe_block_no_safety_comment"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Rust `unsafe { ... }` block without a preceding `// SAFETY:` comment"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_rust(&path) {
                continue;
            }
            if looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_rust(path: &Utf8PathBuf) -> bool {
    path.extension().is_some_and(|ext| ext == "rs")
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
        if !is_unsafe_block_line(line) {
            continue;
        }
        if has_safety_comment_above(&lines, idx) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line));
    }
}

/// True iff `line` contains `unsafe {` as a block-introducer, not as
/// `unsafe fn` / `unsafe trait` / `unsafe impl` / `unsafe extern`.
fn is_unsafe_block_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !contains_unsafe_block(trimmed) {
        return false;
    }
    if is_unsafe_declaration(trimmed) {
        return false;
    }
    true
}

fn contains_unsafe_block(s: &str) -> bool {
    s.contains("unsafe {") || s.contains("unsafe{")
}

fn is_unsafe_declaration(trimmed: &str) -> bool {
    const DECLARATION_PREFIXES: &[&str] = &[
        "unsafe fn ",
        "unsafe trait ",
        "unsafe impl ",
        "unsafe extern ",
        "pub unsafe fn ",
        "pub unsafe trait ",
        "pub(crate) unsafe fn ",
    ];
    DECLARATION_PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// True iff any non-blank line in the prior 5 lines starts with a
/// `// SAFETY:` / `/// SAFETY:` marker (case-insensitive).
fn has_safety_comment_above(lines: &[&str], idx: usize) -> bool {
    let lo = idx.saturating_sub(5);
    for prior in lines[lo..idx].iter().rev() {
        let trimmed = prior.trim();
        if trimmed.is_empty() {
            continue;
        }
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("// SAFETY:") || upper.starts_with("/// SAFETY:") {
            return true;
        }
        if !is_comment_or_attribute(trimmed) {
            // Hit real code — comment is not adjacent to the block.
            return false;
        }
    }
    false
}

fn is_comment_or_attribute(trimmed: &str) -> bool {
    trimmed.starts_with("//") || trimmed.starts_with("#[") || trimmed.starts_with("#![")
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.complete.unsafe_block_no_safety_comment",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`unsafe { ... }` block lacks a preceding `// SAFETY:` comment".into(),
        explanation: "Rust unsafe blocks must document the invariants \
             the compiler cannot check. The clippy lint \
             `undocumented_unsafe_blocks` enforces this — every unsafe \
             scope needs a `// SAFETY:` comment immediately above so a \
             future refactor can verify the invariants still hold."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add a `// SAFETY: <invariant>` comment on the line directly \
             above the `unsafe { ... }` block describing why each unsafe \
             operation inside is sound (alignment, lifetime, aliasing, \
             initialisation, FFI contract)."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
