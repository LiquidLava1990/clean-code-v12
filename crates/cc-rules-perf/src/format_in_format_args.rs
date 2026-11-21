//! `cc.perf.format_in_format_args` — `format!(..., format!(...))` and
//! friends — a nested format builder inside another format builder.
//!
//! Canonical bug:
//! ```text
//! println!("got {}", format!("user_{id}"));
//! write!(out, "{}", format!("{a}/{b}"))?;
//! tracing::info!("answer = {}", format!("{:.3}", x));
//! ```
//! Each inner `format!(...)` allocates a fresh `String`, the outer
//! macro then *re-formats* that `String` through `Display`. The same
//! macro can interpolate the inner template directly with one
//! allocation total — no transient `String`, no double walk.
//!
//! OSS source: clippy `format_in_format_args`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for an outer
//! formatter macro (`format!`, `println!`, `eprintln!`, `print!`,
//! `eprint!`, `write!`, `writeln!`, `info!`, `warn!`, `error!`,
//! `debug!`, `trace!`) whose argument list contains a literal
//! `format!(`. The single-line scan is sound because the `format!(`
//! token cannot legitimately appear elsewhere on a macro-call line.
//! Skip test files and rule-pack source.
//!
//! Severity `Required`, confidence 0.95.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_rust_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 probe R-FORMAT-IN-FORMAT-ARGS.
#[derive(Debug, Default, Clone, Copy)]
pub struct FormatInFormatArgsRule;

const OUTER_MACROS: &[&str] = &[
    "format!(",
    "println!(",
    "eprintln!(",
    "print!(",
    "eprint!(",
    "write!(",
    "writeln!(",
    "info!(",
    "warn!(",
    "error!(",
    "debug!(",
    "trace!(",
];

impl Rule for FormatInFormatArgsRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.format_in_format_args"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "nested `format!(...)` inside an outer formatting macro"
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
            if is_rust_test_path(&path) || looks_like_rule_pack_source(&path) {
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
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(outer) = detect_nested_format(line) {
            out.push(emit(path.clone(), idx + 1, line, outer));
        }
    }
}

/// Returns the matched outer macro name when the line carries a
/// nested `format!(` inside one of the outer formatter macros.
fn detect_nested_format(line: &str) -> Option<&'static str> {
    for outer in OUTER_MACROS {
        let Some(outer_idx) = line.find(outer) else {
            continue;
        };
        let inner_search_from = outer_idx + outer.len();
        if inner_search_from >= line.len() {
            continue;
        }
        if line[inner_search_from..].contains("format!(") {
            return Some(short_label(outer));
        }
    }
    None
}

const fn short_label(macro_call: &str) -> &'static str {
    match macro_call.as_bytes() {
        b"format!(" => "format!",
        b"println!(" => "println!",
        b"eprintln!(" => "eprintln!",
        b"print!(" => "print!",
        b"eprint!(" => "eprint!",
        b"write!(" => "write!",
        b"writeln!(" => "writeln!",
        b"info!(" => "info!",
        b"warn!(" => "warn!",
        b"error!(" => "error!",
        b"debug!(" => "debug!",
        b"trace!(" => "trace!",
        _ => "macro!",
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, outer: &'static str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.format_in_format_args",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "`{outer}` argument is itself a `format!(...)` — \
             one allocation per call could be zero"
        ),
        explanation: format!(
            "Each inner `format!(...)` allocates a fresh `String`. The \
             outer `{outer}` then walks that `String` again through \
             `Display` to produce its own buffer. The same macro can \
             interpolate the inner placeholders directly — \
             `{outer} \"…{{x}}…{{y}}…\", x, y` — for a single \
             allocation and one walk total."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Inline the inner template: replace \
                 `{outer} \"{{}}\", format!(\"…{{x}}…\", x)` with \
                 `{outer} \"…{{x}}…\", x = x` (or the equivalent \
                 `format_args!` pattern). The inner `String` allocation \
                 disappears entirely."
        )),
        snippet,
        weight: 2,
    })
}
