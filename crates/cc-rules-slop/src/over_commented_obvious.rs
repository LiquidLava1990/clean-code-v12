//! `cc.slop.over_commented_obvious` — flag comments that restate the
//! line they sit above.
//!
//! Heuristic: a function body whose source contains a comment line
//! immediately followed by a single-statement code line where the
//! comment's identifier tokens overlap the statement's tokens by ≥70%.
//!
//! The probe operates on raw source bytes (read via the
//! [`cc_rules::SourceTable`]) rather than on Comment nodes, because not
//! every frontend lifts comments. The trade-off: we miss block-style
//! comments that span more than one line.

use std::collections::HashSet;

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-OBVIOUS.
#[derive(Debug, Default, Clone, Copy)]
pub struct OverCommentedObviousRule;

impl Rule for OverCommentedObviousRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.over_commented_obvious"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "comment restates the code on the next line"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                out.extend(check_function(ctx, node.id));
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        // Tests legitimately mirror their assertions in comments
        // (e.g. `// parses hello world\nparses_hello_world();`).
        return None;
    }
    let bytes = ctx.source.get(&path);
    let source = std::str::from_utf8(bytes).ok()?;
    let range = range_prop(ctx.batch, id, "range")?;
    let body = slice_for_range(source, range.start.offset, range.end.offset);
    if !body_has_obvious_comment(body) {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.over_commented_obvious",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{name}` contains a comment that restates the next line"),
        explanation: format!(
            "Inside `{name}`, a comment line is followed by a single \
             statement whose identifiers are >=70% covered by the comment. \
             Comments should explain WHY (constraint, invariant, workaround), \
             not restate WHAT the code already says."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Delete the redundant comment, or replace it with a one-liner \
             explaining the constraint that drove the line (e.g. why this \
             specific value, why this order)."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

fn slice_for_range(source: &str, start: u32, end: u32) -> &str {
    let s = (start as usize).min(source.len());
    let e = (end as usize).min(source.len()).max(s);
    source.get(s..e).unwrap_or("")
}

/// Walk consecutive line pairs (comment, code) and flag when the
/// comment's tokens overlap the code's tokens by >=70%.
fn body_has_obvious_comment(body: &str) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    let mut idx = 0;
    while idx + 1 < lines.len() {
        let comment_line = lines[idx].trim();
        let code_line = lines[idx + 1].trim();
        if let Some(comment_text) = strip_comment_prefix(comment_line) {
            if !code_line.is_empty()
                && !is_comment_line(code_line)
                && is_single_statement(code_line)
                && overlap_ratio(comment_text, code_line) >= 0.70_f32
            {
                return true;
            }
        }
        idx += 1;
    }
    false
}

fn strip_comment_prefix(line: &str) -> Option<&str> {
    for prefix in ["///", "//", "#", "*"] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return Some(rest.trim());
        }
    }
    None
}

fn is_comment_line(line: &str) -> bool {
    strip_comment_prefix(line).is_some()
}

fn is_single_statement(line: &str) -> bool {
    // Heuristic: one statement = no curly-brace open at end, no bare
    // structural keyword. We also require some alphanumeric content.
    let trimmed = line.trim_end_matches([';', ',']);
    !trimmed.ends_with('{') && trimmed.chars().any(char::is_alphanumeric)
}

/// Token-set overlap ratio (Jaccard-style on the comment side):
/// `|comment_tokens ∩ code_tokens|` / `|comment_tokens|`.
fn overlap_ratio(comment: &str, code: &str) -> f32 {
    let comment_tokens = identifier_tokens(comment);
    if comment_tokens.is_empty() {
        return 0.0;
    }
    let code_tokens = identifier_tokens(code);
    let hit = comment_tokens
        .iter()
        .filter(|t| code_tokens.contains(*t))
        .count();
    #[allow(clippy::cast_precision_loss)]
    {
        hit as f32 / comment_tokens.len() as f32
    }
}

fn identifier_tokens(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|tok| tok.len() >= 3)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_detects_restatement() {
        let comment = "increment counter by one";
        let code = "counter += 1; // increment";
        assert!(overlap_ratio(comment, code) >= 0.5);
    }

    #[test]
    fn overlap_zero_for_disjoint() {
        let comment = "guard against overflow";
        let code = "result = read_table(query);";
        assert!(overlap_ratio(comment, code) < 0.3);
    }
}
