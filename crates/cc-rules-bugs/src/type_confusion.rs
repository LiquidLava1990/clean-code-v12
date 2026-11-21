//! `cc.bug.type_confusion` — implicit `Any` / `unknown` / `interface{}`
//! flowing into a typed binding.
//!
//! Phase-3 heuristic: walk every [`NodeKind::Function`] / [`NodeKind::Method`]
//! whose `return_type` property reads as one of the unknown-ish tokens
//! (`Any`, `any`, `unknown`, `interface{}`, `dyn Any`). For each, look at
//! every [`NodeKind::Call`] whose `callee_ref` matches the function name
//! AND that lives inside a [`NodeKind::Write`] whose `target_type` is a
//! concrete annotation (anything other than the unknown-ish tokens).
//!
//! Frontends differ on whether `return_type` is exposed at all; when
//! absent, the probe degrades to silence rather than firing false
//! positives. PDG-aware tightening lives in Phase 4.

use cc_cpg::{Node, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, BugFindingBlueprint,
};

/// Family-3 probe R-TYPE-CONFUSION.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypeConfusionRule;

const UNKNOWN_TYPES: &[&str] = &["Any", "any", "unknown", "interface{}", "dyn Any", "object"];

impl Rule for TypeConfusionRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.type_confusion"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.65)
    }
    fn description(&self) -> &'static str {
        "function returning Any/unknown/interface{} flows into a typed binding"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let unknown_returners = collect_unknown_returners(ctx);
        if unknown_returners.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node, &unknown_returners) {
                out.push(finding);
            }
        }
        out
    }
}

fn collect_unknown_returners(ctx: &RuleContext<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for kind in [NodeKind::Function, NodeKind::Method] {
        for node in nodes_of_kind(ctx.batch, kind) {
            let Some(rt) = string_prop(ctx.batch, node.id, "return_type") else {
                continue;
            };
            if !is_unknown_type(rt) {
                continue;
            }
            if let Some(name) = string_prop(ctx.batch, node.id, "name") {
                names.push(name.to_owned());
            }
        }
    }
    names
}

fn is_unknown_type(t: &str) -> bool {
    let trimmed = t.trim();
    UNKNOWN_TYPES.iter().any(|needle| trimmed == *needle)
}

fn check_write(ctx: &RuleContext<'_>, write: &Node, unknowns: &[String]) -> Option<Finding> {
    let target_type = string_prop(ctx.batch, write.id, "target_type")?;
    if is_unknown_type(target_type) {
        return None;
    }
    let initializer = string_prop(ctx.batch, write.id, "initializer")?;
    let callee = unknowns
        .iter()
        .find(|name| initializer.contains(name.as_str()))?;
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target").unwrap_or("<binding>");
    let location = location_from_node(ctx.batch, write.id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.type_confusion",
        severity: Severity::Required,
        confidence: Confidence::new(0.65),
        location,
        headline: format!(
            "`{target}: {target_type}` is filled from `{callee}()` which returns an untyped value"
        ),
        explanation: format!(
            "`{callee}` returns Any / unknown / interface{{}}; the call site \
             stores its result in `{target}: {target_type}` without an \
             intervening cast or runtime check. The mismatch silently \
             smuggles arbitrary shapes past the type system and surfaces as \
             AttributeError / panic later."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Tighten `{callee}`'s return type to a real schema, or insert a \
             validating cast (`isinstance(..)`, `as Type`, `type assertion`) \
             at the call site before assigning into the typed binding."
        )),
        snippet: initializer.to_owned(),
        weight: 2,
    }))
}
