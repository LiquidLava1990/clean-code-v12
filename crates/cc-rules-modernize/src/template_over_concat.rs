//! `cc.modernize.template_over_concat` — string concatenation across
//! 3+ operands (`"a" + x + " b"`) superseded by a template literal /
//! f-string.
//!
//! Mirrors ESLint `prefer-template`, ruff `FLY002` (`F-string Loves
//! You`), and pylint `consider-using-f-string`. Detection scans
//! [`NodeKind::Literal`] and [`NodeKind::Identifier`] nodes whose
//! `text` / `signature` property reveals a `+`-chained string
//! expression with at least one literal operand. The probe stays
//! Python/JS/TS-only because Rust uses `format!` (covered by the
//! sibling `legacy_format_macro` probe) and Go uses `fmt.Sprintf`.
//!
//! Severity: `Nit` — the rewrite is mechanical; concatenation only
//! becomes a real bug when one operand is an unrelated type.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.template_over_concat`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TemplateOverConcatRule;

const SUPPORTED_EXTS: &[&str] = &[".py", ".js", ".jsx", ".mjs", ".ts", ".tsx"];

const TEXT_KEYS: &[&str] = &["text", "expression", "signature", "value"];

const MIN_OPERANDS: usize = 3;

impl Rule for TemplateOverConcatRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.template_over_concat"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "3+-operand string concat superseded by template literal / f-string"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Literal, NodeKind::Identifier, NodeKind::Read] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let text = expression_text(ctx, node.id)?;
    if !looks_like_string_concat(&text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !SUPPORTED_EXTS
        .iter()
        .any(|ext| path.as_str().ends_with(ext))
    {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.template_over_concat",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "String `+` concatenation should be a template / f-string".into(),
        explanation: "Concatenating three or more operands with `+` builds a \
             new intermediate `String` per join, hides the final layout \
             behind operator chains, and silently coerces non-string \
             operands. A template literal (`` `foo ${x} bar` ``) or Python \
             f-string (`f\"foo {x} bar\"`) keeps the literal layout visible \
             and avoids the temporaries."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `\"a \" + x + \" b\"` with `` `a ${x} b` `` (JS/TS) or \
             `f\"a {x} b\"` (Python). For deferred/lazy strings prefer \
             `String.prototype.concat` only when interpolation is impossible."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}

fn expression_text(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in TEXT_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn looks_like_string_concat(text: &str) -> bool {
    if !text.contains('+') {
        return false;
    }
    if !contains_string_literal(text) {
        return false;
    }
    let operands = split_concat_operands(text);
    operands >= MIN_OPERANDS
}

fn contains_string_literal(text: &str) -> bool {
    text.contains('"') || text.contains('\'')
}

fn split_concat_operands(text: &str) -> usize {
    let mut count = 1usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_back = false;
    let mut prev_escape = false;
    for ch in text.chars() {
        if prev_escape {
            prev_escape = false;
            continue;
        }
        match ch {
            '\\' => prev_escape = true,
            '\'' if !in_double && !in_back => in_single = !in_single,
            '"' if !in_single && !in_back => in_double = !in_double,
            '`' if !in_single && !in_double => in_back = !in_back,
            '+' if !in_single && !in_double && !in_back => count += 1,
            _ => {}
        }
    }
    count
}
