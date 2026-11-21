//! Tier-0 forever rule R-BOOL-COMPLEXITY.
//!
//! Flag a single boolean expression chaining more than [`MAX_OPERANDS`]
//! operands joined by `&&` / `||` (Rust/Go/TS) or ` and ` / ` or `
//! (Python). Threshold mirrors Ruff's `PLR0916 too-many-boolean-expressions`
//! ceiling of 5: a sixth operand is the line at which the boolean
//! becomes a parser instead of an assertion.
//!
//! The CPG does not yet emit `BinaryOp` nodes, so this probe falls back
//! to per-line byte scanning over the function body. It is precise on
//! single-line booleans and conservative on multi-line ones (only flags
//! when *one logical line* exceeds the threshold; two short conjunctions
//! across two lines do not stack).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, Tier0FindingBlueprint,
};

/// Threshold cited from Ruff `PLR0916 too-many-boolean-expressions`
/// (default 5).
// TODO(W2): wire ctx.config thresholds
const MAX_OPERANDS: u32 = 5;

/// Tier-0 forever rule R-BOOL-COMPLEXITY.
#[derive(Debug, Default, Clone, Copy)]
pub struct BooleanComplexityRule;

impl Rule for BooleanComplexityRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.boolean_complexity"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "boolean expression chains more than 5 operands"
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

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let range = range_prop(ctx.batch, id, "range")?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    let body = byte_window(bytes, range.start.offset, range.end.offset);
    let language = enclosing_language(ctx, id);
    let max_operands = max_operands_per_line(body, language.as_deref());
    if max_operands <= MAX_OPERANDS {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = max_operands.saturating_sub(MAX_OPERANDS);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.boolean_complexity",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "function `{name}` has a boolean with {max_operands} operands (threshold {MAX_OPERANDS})"
        ),
        explanation: format!(
            "A boolean chain with {max_operands} operands is a parser, not an assertion. \
             Tier-0 caps at {MAX_OPERANDS}; extract sub-predicates into named helpers."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract the boolean into one or more well-named predicate functions \
             (`is_eligible`, `has_active_session`); compose them with at most a single `&&`."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Walk the AST_PARENT chain to the enclosing File and read its
/// `language` property.
fn enclosing_language(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    let mut cur = id;
    for _ in 0..256_u16 {
        if node_kind(ctx.batch, cur) == Some(NodeKind::File) {
            return string_prop(ctx.batch, cur, "language").map(str::to_owned);
        }
        cur = ast_parent(ctx.batch, cur)?;
    }
    None
}

/// For each line in `body`, count operands joined by the language's
/// boolean operators. Operand count = operator count + 1. Returns the
/// max operand count across lines.
fn max_operands_per_line(body: &[u8], language: Option<&str>) -> u32 {
    let text = std::str::from_utf8(body).unwrap_or("");
    let mut max_ops: u32 = 0;
    for line in text.lines() {
        let ops = count_operators_on_line(line, language);
        if ops > 0 {
            let operands = ops.saturating_add(1);
            if operands > max_ops {
                max_ops = operands;
            }
        }
    }
    max_ops
}

fn count_operators_on_line(line: &str, language: Option<&str>) -> u32 {
    if is_python(language) {
        count_python_word_ops(line)
    } else {
        count_symbol_ops(line)
    }
}

fn is_python(language: Option<&str>) -> bool {
    matches!(language, Some("python" | "py"))
}

/// Count `&&` and `||` occurrences. Each is exactly two chars so there
/// is no ambiguity with bitwise `&` / `|`.
fn count_symbol_ops(line: &str) -> u32 {
    let bytes = line.as_bytes();
    let mut count: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if (bytes[i] == b'&' && bytes[i + 1] == b'&') || (bytes[i] == b'|' && bytes[i + 1] == b'|')
        {
            count = count.saturating_add(1);
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}

/// Count whole-word `and` / `or` operators. Whole-word matching ensures
/// we don't catch `band`, `random`, `for`. We require both flanking
/// characters to be non-alphanumeric.
fn count_python_word_ops(line: &str) -> u32 {
    let mut count: u32 = 0;
    for word in [" and ", " or "] {
        count = count.saturating_add(count_substring(line, word));
    }
    count
}

fn count_substring(haystack: &str, needle: &str) -> u32 {
    let mut count: u32 = 0;
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() || bytes.len() < needle_bytes.len() {
        return 0;
    }
    let mut i = 0;
    while i + needle_bytes.len() <= bytes.len() {
        if &bytes[i..i + needle_bytes.len()] == needle_bytes {
            count = count.saturating_add(1);
            i += needle_bytes.len();
        } else {
            i += 1;
        }
    }
    count
}
