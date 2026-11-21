//! `cc.modernize.django_url_path_param_required` — Django
//! `path('<param>/', view)` where `<param>` lacks a converter prefix
//! (`<int:param>`, `<slug:param>`, etc.).
//!
//! Mirrors ruff `DJ001` family (django-untyped-converter).
//!
//! Phase-10 detector: scan every `.py` file once. For each line that
//! looks like a `path(...)` / `re_path(...)` call, locate the literal
//! pattern argument and inspect every `<...>` capture. A capture
//! without a `:` (`<param>`) defaults to `str` matching everything
//! between slashes — usually wrong: integer IDs accept text, slug
//! routes accept `/` characters, etc. Flag.
//!
//! Severity: `Required`. Confidence 0.85 — relies on a textual
//! `path('<...>')` shape; some codebases wrap `path` in a helper that
//! adds converters dynamically.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.django_url_path_param_required`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DjangoUrlPathParamRequiredRule;

const PATH_CALLEES: &[&str] = &["path(", "re_path(", "django.urls.path(", "urls.path("];

impl Rule for DjangoUrlPathParamRequiredRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.django_url_path_param_required"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Django `path('<param>/', ...)` capture without converter (`<int:>`, `<slug:>`, ...)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
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
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(missing) = find_untyped_capture(line) {
            out.push(emit(path.clone(), line_idx + 1, line, &missing));
        }
    }
}

/// Return the first `<...>` capture missing a `:` converter, or `None`.
fn find_untyped_capture(line: &str) -> Option<String> {
    if !line_contains_path_call(line) {
        return None;
    }
    let pattern = extract_first_string_literal(line)?;
    for capture in iter_angle_captures(&pattern) {
        if !capture.contains(':') && !capture.is_empty() {
            return Some(capture);
        }
    }
    None
}

fn line_contains_path_call(line: &str) -> bool {
    PATH_CALLEES.iter().any(|callee| {
        line.find(callee)
            .is_some_and(|idx| !is_token_continuation(line, idx))
    })
}

fn is_token_continuation(line: &str, idx: usize) -> bool {
    if idx == 0 {
        return false;
    }
    let prev = line.as_bytes()[idx - 1];
    prev.is_ascii_alphanumeric() || prev == b'_'
}

/// Extract the first quoted string literal on the line.
fn extract_first_string_literal(line: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(start) = line.find(quote) {
            let rest = &line[start + 1..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_owned());
            }
        }
    }
    None
}

/// Yield each `<...>` substring (without the angle brackets).
fn iter_angle_captures(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = pattern.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'<' {
            if let Some(close_rel) = pattern[idx + 1..].find('>') {
                let inner = &pattern[idx + 1..idx + 1 + close_rel];
                out.push(inner.to_owned());
                idx += 1 + close_rel + 1;
                continue;
            }
        }
        idx += 1;
    }
    out
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, missing: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.django_url_path_param_required",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("Django path capture `<{missing}>` lacks a converter prefix"),
        explanation: format!(
            "`path('...<{missing}>...')` without a converter defaults to \
             `str`, which matches anything except `/`. That is almost \
             never what the view expects: integer ID routes silently \
             accept `'foo'` and the view crashes downstream; slug routes \
             accept `'.'` and break canonical URLs. The view function \
             then has to re-validate, which Django's typed converters \
             already do for free."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add an explicit converter to the capture: \
             `<int:{missing}>` for numeric IDs, \
             `<slug:{missing}>` for slug strings, \
             `<uuid:{missing}>` for UUID4, \
             `<path:{missing}>` when the value really may contain `/`. \
             Custom converters subclass `django.urls.converters.\
             StringConverter`."
        )),
        snippet,
        weight: 2,
    })
}
