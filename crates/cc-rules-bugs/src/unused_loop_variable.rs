//! `cc.bug.unused_loop_variable` — Python `for x in lst: ...` where the
//! body never references `x`. The variable is dead — likely either a
//! typo or a leftover from a refactor.
//!
//! Mirrors ruff `B007` (unused-loop-control-variable).
//!
//! Phase-9 detector: locate every [`NodeKind::Loop`] whose `header`
//! looks like `for X in Y` (Python). Read the loop body bytes from the
//! source table; if the body never mentions `X` as an identifier, flag.
//! Skip the canonical placeholder names `_` and `__`.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.unused_loop_variable`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnusedLoopVariableRule;

impl Rule for UnusedLoopVariableRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.unused_loop_variable"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Python `for x in …` whose body never references `x`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for loop_node in nodes_of_kind(ctx.batch, NodeKind::Loop) {
            if let Some(finding) = check_loop(ctx, loop_node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_loop(ctx: &RuleContext<'_>, loop_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, loop_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if path.extension() != Some("py") {
        return None;
    }
    let header = string_prop(ctx.batch, loop_id, "header").unwrap_or("");
    let var = parse_python_iter_variable(header)?;
    if is_placeholder(&var) {
        return None;
    }
    let body = body_text(ctx, loop_id, &path)?;
    if body_references_identifier(&body, &var) {
        return None;
    }
    let location = location_from_node(ctx.batch, loop_id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.unused_loop_variable",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("loop variable `{var}` is never read in the body"),
        explanation: format!(
            "The loop binds `{var}` on every iteration, but the body \
             never references it. This is usually one of: a typo (the \
             body uses a similarly-named binding), dead code from a \
             refactor, or a counted iteration that should use \
             `for _ in …` to make the intent explicit."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Either reference `{var}` inside the body, rename the \
             variable to `_` to mark it deliberately unused, or replace \
             the loop with `for _ in range(len(…))` / a count-based form \
             when only the iteration count matters."
        )),
        snippet: header.to_owned(),
        weight: 2,
    }))
}

fn parse_python_iter_variable(header: &str) -> Option<String> {
    let trimmed = header.trim_start();
    let after_for = trimmed.strip_prefix("for ")?.trim_start();
    let in_idx = after_for.find(" in ")?;
    let var_segment = after_for[..in_idx].trim();
    if var_segment.is_empty() || var_segment.contains(',') || var_segment.contains('(') {
        return None;
    }
    if !var_segment.chars().all(is_ident_char) {
        return None;
    }
    Some(var_segment.to_owned())
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_placeholder(var: &str) -> bool {
    var == "_" || var == "__" || var.starts_with('_')
}

fn body_text(ctx: &RuleContext<'_>, loop_id: NodeId, path: &Utf8PathBuf) -> Option<String> {
    let range = range_prop(ctx.batch, loop_id, "range")?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    let header = string_prop(ctx.batch, loop_id, "header").unwrap_or("");
    let header_len = header.len();
    let start = (range.start.offset as usize).saturating_add(header_len);
    let end = (range.end.offset as usize).min(bytes.len()).max(start);
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()
        .map(str::to_owned)
}

fn body_references_identifier(body: &str, var: &str) -> bool {
    let mut idx = 0;
    while let Some(found) = body[idx..].find(var) {
        let abs = idx + found;
        let before_ok = abs == 0 || !is_ident_char_byte(body.as_bytes()[abs - 1]);
        let after_pos = abs + var.len();
        let after_ok = after_pos >= body.len() || !is_ident_char_byte(body.as_bytes()[after_pos]);
        if before_ok && after_ok {
            return true;
        }
        idx = abs + var.len();
    }
    false
}

fn is_ident_char_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
