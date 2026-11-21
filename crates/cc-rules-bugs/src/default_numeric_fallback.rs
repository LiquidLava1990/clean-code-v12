//! `cc.bug.default_numeric_fallback` — module-level `let x = NUM;`
//! where `NUM` is an unsuffixed numeric literal whose type defaults to
//! `i32` / `f64` purely because the compiler had nowhere to look.
//!
//! Canonical bug:
//! ```text
//! const RETRIES = 5;            // inferred as i32 — dies on portable APIs
//! static THRESHOLD = 0.95;      // inferred as f64 — surprises f32 callers
//! ```
//! Inside a function body the surrounding type context usually
//! disambiguates, but at module scope there is no surrounding code to
//! constrain inference. The literal silently becomes `i32` / `f64`,
//! and the next caller that wants `usize` / `f32` discovers it via a
//! `mismatched types` error miles from the declaration.
//!
//! OSS source: clippy `default_numeric_fallback`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files. Look at lines
//! whose left margin is column 0 (truly module-level) starting with
//! `const ` / `static ` / `let ` and matching `= <number>;` with no
//! type annotation and no numeric suffix on the literal. Skip test
//! files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.75.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-DEFAULT-NUMERIC-FALLBACK.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultNumericFallbackRule;

const NUMERIC_SUFFIXES: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64",
];

impl Rule for DefaultNumericFallbackRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.default_numeric_fallback"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "module-level numeric literal without a type annotation defaults to `i32`/`f64`"
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
    for (idx, line) in text.lines().enumerate() {
        if !is_module_level_line(line) {
            continue;
        }
        if let Some(default_ty) = detect_unsuffixed_module_decl(line) {
            out.push(emit(path.clone(), idx + 1, line, default_ty));
        }
    }
}

/// True iff `line` starts at column 0 and isn't a comment / attribute.
/// Module-scope items in Rust live at the file's top level — anything
/// indented sits inside a function / impl / mod block.
fn is_module_level_line(line: &str) -> bool {
    if line.starts_with(' ') || line.starts_with('\t') {
        return false;
    }
    let trimmed = line.trim_start();
    !(trimmed.starts_with("//") || trimmed.starts_with("#"))
}

/// Returns `"i32"` / `"f64"` when the line is `const X = LIT;` / `static X = LIT;` /
/// `let X = LIT;` with no `: TYPE` annotation and no numeric suffix on the literal.
fn detect_unsuffixed_module_decl(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    let rest = match strip_decl_keyword(trimmed) {
        Some(r) => r,
        None => return None,
    };
    let eq_idx = rest.find('=')?;
    let lhs = rest[..eq_idx].trim();
    if lhs.contains(':') {
        return None; // typed binding
    }
    let after_eq = rest[eq_idx + 1..].trim_start();
    let semi = after_eq.find(';')?;
    let value = after_eq[..semi].trim();
    classify_numeric_literal(value)
}

fn strip_decl_keyword(s: &str) -> Option<&str> {
    for kw in ["const ", "static ", "let "] {
        if let Some(rest) = s.strip_prefix(kw) {
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            return Some(rest);
        }
    }
    None
}

/// Returns `"i32"` for an unsuffixed integer literal, `"f64"` for an
/// unsuffixed float literal, `None` for anything else (suffixed
/// literal, expression, string, etc.).
fn classify_numeric_literal(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return None;
    }
    if has_numeric_suffix(value) {
        return None;
    }
    let core = value.replace('_', "");
    let bytes = core.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut seen_dot = false;
    for &b in bytes {
        if b == b'.' {
            if seen_dot {
                return None;
            }
            seen_dot = true;
            continue;
        }
        if !b.is_ascii_digit() {
            return None;
        }
    }
    Some(if seen_dot { "f64" } else { "i32" })
}

fn has_numeric_suffix(value: &str) -> bool {
    NUMERIC_SUFFIXES.iter().any(|s| value.ends_with(s))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, default_ty: &'static str) -> Finding {
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
        rule_id: "cc.bug.default_numeric_fallback",
        severity: Severity::Nit,
        confidence: Confidence::new(0.75),
        location,
        headline: format!("module-level numeric literal silently inferred as `{default_ty}`"),
        explanation: "At module scope there is no surrounding type context to \
             pin the literal's type, so Rust falls back to the \
             defaults: `i32` for integers, `f64` for floats. The next \
             caller that wants `usize` / `u64` / `f32` discovers the \
             mismatch through a confusing `expected u64, found i32` \
             far from the declaration."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Annotate the binding (`const RETRIES: u32 = 5;`) or \
             suffix the literal (`const RETRIES = 5_u32;`). Either \
             form pins the type at the source so callers fail at the \
             use site, not the declaration."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
