//! `cc.docs.docstring_signature_drift` — flag mismatch between the
//! parameter list named inside a Python-style `:param x:` docstring
//! and the function's actual [`NodeKind::Parameter`] children.
//!
//! Phase-5 simplification: only `:param <name>:` (Sphinx) is parsed.
//! `@param` (JSDoc / JavaDoc) and `* @param` are recognised as future
//! patterns in `crate::helpers::DOCSTRING_PARAM_PATTERNS` but the
//! Phase-5 implementation skips them — those languages' docstring
//! conventions vary too much for a single regex pass.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_parameter_names, location_from_node,
    preceding_comment, DocsFindingBlueprint, DOCSTRING_PARAM_PATTERNS,
};

/// Maximum line gap between the docstring comment's last line and the
/// function's start line for the rule to associate the two.
const MAX_DOCSTRING_GAP: u32 = 2;

/// Family-16 probe R-DOCS-DOCSTRING-SIGNATURE-DRIFT.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocstringSignatureDriftRule;

impl Rule for DocstringSignatureDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.docstring_signature_drift"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "docstring `:param` list drifts from function signature"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, function_id: NodeId) -> Option<Finding> {
    let comment_id = preceding_comment(ctx.batch, function_id, MAX_DOCSTRING_GAP)?;
    let docstring = comment_text(ctx, comment_id)?;
    let documented = collect_param_names(docstring);
    if documented.is_empty() {
        return None;
    }
    let actual = function_parameter_names(ctx.batch, function_id);
    let drift = describe_drift(&documented, &actual)?;
    let path = enclosing_file_path(ctx.batch, function_id)?;
    let location = location_from_node(ctx.batch, function_id, path);
    let name = string_prop(ctx.batch, function_id, "name").unwrap_or("<anonymous>");
    Some(build_finding(DocsFindingBlueprint {
        rule_id: "cc.docs.docstring_signature_drift",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("docstring drifts from `{name}` signature"),
        explanation: format!(
            "The docstring lists params {documented:?} but the function \
             actually accepts {actual:?}. {drift} Drifted docstrings \
             mislead callers and rot faster than the code itself."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Update the `:param` lines to match the actual signature, \
             or update the signature to match the documented intent."
                .into(),
        ),
        snippet: docstring.lines().next().unwrap_or(docstring).to_owned(),
        weight: 2,
    }))
}

fn comment_text<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    string_prop(ctx.batch, id, "text").or_else(|| string_prop(ctx.batch, id, "value"))
}

/// Extract every `:param <name>:` token from `text`. Robust to leading
/// whitespace, leading `*` (sphinx with star-prefixed continuation),
/// and trailing type annotations.
fn collect_param_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        if let Some(name) = parse_param_line(line) {
            names.push(name);
        }
    }
    names
}

/// Return the parameter name from a single line if it carries a
/// `:param <name>:` token. Type annotations (`:param int x:`) are
/// stripped — the trailing whitespace-separated token before the
/// closing `:` wins.
///
/// Phase-5 only honours the Sphinx (`:param `) prefix; the JSDoc /
/// JavaDoc prefixes registered in [`DOCSTRING_PARAM_PATTERNS`] are
/// reserved for Phase-6 expansion.
fn parse_param_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start_matches(|c: char| c.is_whitespace() || c == '*');
    if !DOCSTRING_PARAM_PATTERNS
        .iter()
        .any(|p| trimmed.starts_with(p))
    {
        return None;
    }
    let rest = trimmed.strip_prefix(":param ")?;
    let close = rest.find(':')?;
    let head = rest[..close].trim();
    if head.is_empty() {
        return None;
    }
    let last_token = head.split_whitespace().last()?;
    Some(last_token.to_owned())
}

/// Compare two ordered name lists and return a one-sentence summary of
/// the drift, or `None` if they match exactly. Bag-equality is the
/// criterion: order does not matter, but every documented name must
/// appear in the signature and vice-versa.
fn describe_drift(documented: &[String], actual: &[String]) -> Option<String> {
    let mut missing_in_signature: Vec<&str> = documented
        .iter()
        .filter(|n| !actual.iter().any(|a| a == *n))
        .map(String::as_str)
        .collect();
    let mut missing_in_docstring: Vec<&str> = actual
        .iter()
        .filter(|n| !documented.iter().any(|d| d == *n))
        .map(String::as_str)
        .collect();
    if missing_in_signature.is_empty() && missing_in_docstring.is_empty() {
        return None;
    }
    missing_in_signature.sort_unstable();
    missing_in_docstring.sort_unstable();
    Some(format!(
        "Documented but absent: {missing_in_signature:?}; \
         present but undocumented: {missing_in_docstring:?}."
    ))
}
