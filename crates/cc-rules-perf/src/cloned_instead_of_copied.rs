//! `cc.perf.cloned_instead_of_copied` — `.iter().cloned()` on an
//! iterator over `Copy` scalars should be `.iter().copied()`.
//!
//! Canonical pattern:
//! ```text
//! let xs: &[u32] = &[1, 2, 3];
//! let v: Vec<u32> = xs.iter().cloned().collect();   // slow path
//! let v: Vec<u32> = xs.iter().copied().collect();   // ~equivalent codegen,
//!                                                   // but `Copy`-bounded
//! ```
//! On `Copy` types `cloned` and `copied` produce the same machine code
//! today, but `cloned` accepts non-`Copy` types so it suppresses
//! diagnostics when callers later swap the element type for one whose
//! `Clone` is expensive (e.g. `Arc<T>`). `copied` keeps the contract
//! honest.
//!
//! OSS source: clippy `cloned_instead_of_copied`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for `<binding>` of
//! type `&[T]` / `[T; N]` / `Vec<T>` where `T` is a primitive scalar,
//! then later `<binding>.iter().cloned()` on the same line or after.
//! Track types from `let <name>: &[T]` style annotations and from
//! function parameter types.
//!
//! Confidence 0.85 — heuristic; ignores generic flow.

use std::collections::HashMap;

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, identifier_ending_at, is_rust_test_path, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 probe R-CLONED-INSTEAD-OF-COPIED.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClonedInsteadOfCopiedRule;

const COPY_SCALARS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64", "bool", "char",
];

impl Rule for ClonedInsteadOfCopiedRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.cloned_instead_of_copied"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "`.cloned()` on a Copy-element iterator should be `.copied()`"
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
    let mut bindings: HashMap<String, String> = HashMap::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        record_copy_bindings(line, &mut bindings);
        if let Some(name) = detect_cloned_call(line, &bindings) {
            out.push(emit(path.clone(), idx + 1, line, &name));
        }
    }
}

/// Track bindings declared `&[<scalar>]`, `[<scalar>; N]`, `Vec<scalar>`.
/// Flat — one needle at a time, depth <= 3.
fn record_copy_bindings(line: &str, bindings: &mut HashMap<String, String>) {
    for scalar in COPY_SCALARS {
        for needle in copy_binding_needles(scalar) {
            record_one_needle(line, &needle, scalar, bindings);
        }
    }
}

fn copy_binding_needles(scalar: &str) -> [String; 4] {
    [
        format!(": &[{scalar}]"),
        format!(": Vec<{scalar}>"),
        format!(": [{scalar};"),
        format!(": &[{scalar};"),
    ]
}

fn record_one_needle(
    line: &str,
    needle: &str,
    scalar: &str,
    bindings: &mut HashMap<String, String>,
) {
    let mut start = 0;
    while let Some(idx) = line[start..].find(needle) {
        let absolute = start + idx;
        if let Some(name) = identifier_ending_at(line, absolute) {
            bindings.insert(name.to_owned(), scalar.to_owned());
        }
        start = absolute + needle.len();
    }
}

/// Returns the binding name when the line contains
/// `<binding>.iter().cloned()` and the binding is a tracked Copy type.
fn detect_cloned_call(line: &str, bindings: &HashMap<String, String>) -> Option<String> {
    let needle = ".iter().cloned()";
    let idx = line.find(needle)?;
    let pre = &line[..idx];
    let name = identifier_ending_at(pre, pre.len())?;
    if bindings.contains_key(name) {
        return Some(name.to_owned());
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
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
        rule_id: "cc.perf.cloned_instead_of_copied",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name}.iter().cloned()` over a Copy element should be `.copied()`"),
        explanation: "`.cloned()` accepts any `Clone` element, while `.copied()` \
             requires `Copy`. On a `Copy` element the two compile to \
             identical machine code, but `cloned()` silently absorbs \
             a future type change to a non-Copy `Clone` (`Arc<T>`, \
             `String`, `Box<dyn ...>`) — and that path is much slower. \
             Using `copied()` makes the contract explicit and surfaces \
             the regression at compile time."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `.iter().cloned()` with `.iter().copied()`. If a \
             future refactor changes the element to a non-Copy type, \
             the call site fails to compile and you can decide \
             whether the deep clone is intended."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
