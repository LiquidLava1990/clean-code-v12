//! `cc.bug.govet_unkeyed_composite` — Go positional struct literal
//! `Foo{1, "bar", true}` instead of the keyed form `Foo{A: 1, B: "bar",
//! C: true}`. Positional literals are fragile against field re-order and
//! field addition: swapping two fields in the struct definition still
//! compiles, but every positional literal silently gets the wrong
//! values.
//!
//! Mirrors `go vet` `composites`. Severity::Nit by request — the bug is
//! latent until a struct edit, but when it fires it tends to be
//! catastrophic (silent semantic change with no compile error).
//!
//! Phase-11 source-byte detector: `.go` files only (excluding
//! `_test.go`). Match every `<TypeName>{<token>, <token>, ...}` literal
//! with at least two comma-separated values where no value contains
//! `:` (the keyed-form delimiter). Skip slice / map / array literals
//! (`[]Foo{...}` / `[N]Foo{...}` / `map[K]V{...}`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_unkeyed_composite`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetUnkeyedCompositeRule;

impl Rule for GovetUnkeyedCompositeRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_unkeyed_composite"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "positional struct literal `Foo{1, \"bar\"}` is fragile against field reorder"
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
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
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
        if let Some(type_name) = find_unkeyed_literal(line) {
            out.push(emit(path.clone(), idx + 1, line, type_name));
        }
    }
}

/// Return the type name when this line contains a positional struct
/// literal of shape `<TypeName>{<token>, <token>, ...}`.
fn find_unkeyed_literal(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("type ") {
        return None;
    }
    let bytes = line.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = line[start..].find('{') {
        let abs = start + rel;
        start = abs + 1;
        let Some(type_name) = identifier_before(bytes, abs) else {
            continue;
        };
        if !is_likely_struct_typename(&type_name) {
            continue;
        }
        if has_collection_prefix(bytes, abs - type_name.len()) {
            continue;
        }
        let Some(end) = matching_close_brace(bytes, abs) else {
            continue;
        };
        let inner = &line[abs + 1..end];
        if is_unkeyed_multi(inner) {
            return Some(type_name);
        }
    }
    None
}

fn identifier_before(bytes: &[u8], brace_idx: usize) -> Option<String> {
    let mut start = brace_idx;
    while start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == brace_idx {
        return None;
    }
    let raw = std::str::from_utf8(&bytes[start..brace_idx]).ok()?;
    let last_segment = raw.rsplit('.').next().unwrap_or(raw);
    if last_segment.is_empty() {
        return None;
    }
    Some(last_segment.to_owned())
}

/// Heuristic: capitalised first letter looks like an exported type.
/// Avoid lowercase identifiers (`if`, `for`, function names) and the
/// special blank `_`.
fn is_likely_struct_typename(name: &str) -> bool {
    let Some(first) = name.chars().next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    !matches!(name, "T" | "B" | "M")
}

/// True iff the bytes immediately preceding the type name are part of
/// a collection prefix: `]Foo{...}` (slice/array) or `]Foo` after a
/// `map[K]` form. Skip those — the inner items are themselves struct
/// literals whose type is implicit.
fn has_collection_prefix(bytes: &[u8], type_start: usize) -> bool {
    if type_start == 0 {
        return false;
    }
    bytes[type_start - 1] == b']'
}

fn matching_close_brace(bytes: &[u8], open_idx: usize) -> Option<usize> {
    let mut depth = 1i32;
    for (offset, b) in bytes.iter().enumerate().skip(open_idx + 1) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// True iff `inner` is `<x>, <x>, ...` (>=2 values, no `:` between
/// commas, no enclosed `{`/`}`/`(`/`)` group). Conservative: only
/// flag literal-only positional arguments to keep false positives low.
fn is_unkeyed_multi(inner: &str) -> bool {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('{') || trimmed.contains('}') {
        return false;
    }
    let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    let parts: Vec<&&str> = parts.iter().filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|p| !p.contains(':'))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, type_name: String) -> Finding {
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
        rule_id: "cc.bug.govet_unkeyed_composite",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "positional struct literal for `{type_name}` — fragile against field reorder"
        ),
        explanation: format!(
            "`{type_name}{{a, b, c}}` binds values to fields by \
             position. Adding or reordering fields in the struct \
             definition silently shifts every positional literal — the \
             code still compiles, but every site assigns to the wrong \
             field. The keyed form pins the field name and survives \
             every refactor."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rewrite as a keyed literal: `{type_name}{{Field1: a, \
             Field2: b, Field3: c}}`. Most editors offer this refactor \
             automatically. The keyed form also documents intent — the \
             reader sees which value maps to which slot without \
             cross-referencing the type definition."
        )),
        snippet,
        weight: 1,
    })
}
