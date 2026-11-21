//! `cc.bug.mutate_during_iteration` — Python `for x in lst: lst.append(...)`
//! and similar mutate-during-iteration patterns.
//!
//! Iterating a list while mutating it is a classic bug:
//!
//! - Python: `RuntimeError: dictionary changed size during iteration` for
//!   dicts; for lists the iteration silently skips elements or loops
//!   forever depending on the mutation.
//! - Rust: enforced by the borrow checker, so this probe doesn't apply.
//! - Go: `range` reads a snapshot of the slice header, so appends are
//!   silently ignored — different bug, similar smell.
//!
//! Phase-7 detector: locate every [`NodeKind::Loop`] whose `header`
//! looks like `for X in Y:` (Python). Read the loop body bytes from the
//! source table; if the body contains `Y.append(`, `Y.pop(`, `Y.remove(`,
//! `Y.extend(`, `Y.clear(`, `del Y[`, flag.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-MUTATE-DURING-ITERATION.
#[derive(Debug, Default, Clone, Copy)]
pub struct MutateDuringIterationRule;

const MUTATING_METHODS: &[&str] = &[
    ".append(",
    ".extend(",
    ".pop(",
    ".remove(",
    ".clear(",
    ".insert(",
    ".popitem(",
    ".update(",
];

impl Rule for MutateDuringIterationRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.mutate_during_iteration"
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
        "loop body mutates the collection it is iterating"
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
    let collection = parse_python_iter_collection(header)?;
    let body = body_text(ctx, loop_id, &path)?;
    let method = first_mutating_method(&body, &collection)?;
    let location = location_from_node(ctx.batch, loop_id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.mutate_during_iteration",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("loop iterates `{collection}` and mutates it via `{method}`"),
        explanation: format!(
            "The loop iterates over `{collection}` and the body calls \
             `{collection}{method}…)`. In CPython this either raises \
             `RuntimeError: dictionary changed size during iteration` (for \
             dicts) or silently skips / re-visits elements (for lists). The \
             effect depends on the exact mutation and is rarely what the \
             author intended."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Iterate over a snapshot copy: `for x in list({collection}): …`, \
             or build a new collection in a comprehension and reassign at \
             the end: `{collection} = [x for x in {collection} if keep(x)]`. \
             For dicts use `for k in list({collection}.keys()):` then mutate."
        )),
        snippet: header.to_owned(),
        weight: 3,
    }))
}

fn parse_python_iter_collection(header: &str) -> Option<String> {
    let trimmed = header.trim_start();
    if !trimmed.starts_with("for ") {
        return None;
    }
    let after_for = trimmed.strip_prefix("for ")?.trim_start();
    let in_idx = after_for.find(" in ")?;
    let after_in = after_for[in_idx + 4..].trim_start();
    let collection: String = after_in
        .chars()
        .take_while(|c| !matches!(c, ':' | ' ' | ',' | '(' | '['))
        .collect();
    if collection.is_empty() {
        return None;
    }
    Some(collection)
}

fn body_text(ctx: &RuleContext<'_>, loop_id: NodeId, path: &Utf8PathBuf) -> Option<String> {
    let range = range_prop(ctx.batch, loop_id, "range")?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    let start = range.start.offset as usize;
    let end = (range.end.offset as usize).min(bytes.len()).max(start);
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()
        .map(str::to_owned)
}

fn first_mutating_method<'a>(body: &str, collection: &str) -> Option<&'a str> {
    for method in MUTATING_METHODS {
        let needle = format!("{collection}{method}");
        if body.contains(&needle) {
            return Some(method);
        }
    }
    None
}
