//! `cc.bug.equals_hashcode_pair` — class overrides `__eq__` (Python) or
//! `equals` (TS / Java-style) without the matching `__hash__` /
//! `hashCode` partner, or vice versa.
//!
//! Heuristic: enumerate every [`NodeKind::Class`]. For each class, walk
//! the immediate AST children that are [`NodeKind::Method`] /
//! [`NodeKind::Function`] and collect the set of method names. Flag the
//! class when one half of the pair appears without the other.
//!
//! Pairs covered:
//!
//! - Python: `__eq__` ↔ `__hash__`
//! - TypeScript / JavaScript / Java-style: `equals` ↔ `hashCode`
//!
//! Phase-7 conservative — only the immediate child methods are inspected
//! (no walk through nested bodies). Mixin-via-decorator support is
//! deferred until frontends emit a `mixin_hashcode` marker.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-EQUALS-HASHCODE.
#[derive(Debug, Default, Clone, Copy)]
pub struct EqualsHashcodePairRule;

/// One pair: `(left_member, right_member, language_label)`.
const PAIRS: &[(&str, &str, &str)] = &[
    ("__eq__", "__hash__", "Python"),
    ("equals", "hashCode", "TS/Java-style"),
];

impl Rule for EqualsHashcodePairRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.equals_hashcode_pair"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "class defines one half of the equals/hashCode pair without the other"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for class in nodes_of_kind(ctx.batch, NodeKind::Class) {
            if let Some(finding) = check_class(ctx, class.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_class(ctx: &RuleContext<'_>, class: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, class)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let names = collect_method_names(ctx, class);
    let (left, right, language) = find_unbalanced_pair(&names)?;
    let class_name = string_prop(ctx.batch, class, "name").unwrap_or("<class>");
    let location = location_from_node(ctx.batch, class, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.equals_hashcode_pair",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("class `{class_name}` defines `{left}` without `{right}` ({language})"),
        explanation: format!(
            "Equality and hashing must agree: two values that compare equal \
             must hash equal, otherwise hash-keyed collections (set / dict / \
             HashMap) silently corrupt. `{class_name}` overrides `{left}` \
             but not `{right}`, so instances inserted into a hash-keyed \
             container will be unfindable or duplicated."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Implement `{right}` to mirror `{left}`. If the class is \
             intentionally unhashable (mutable identity), set `{right} = None` \
             (Python) or document the asymmetry with an explanatory comment + \
             throw on `{right}` (Java/TS)."
        )),
        snippet: class_name.to_owned(),
        weight: 4,
    }))
}

fn collect_method_names(ctx: &RuleContext<'_>, class: NodeId) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for child in ast_children(ctx.batch, class) {
        if !matches!(
            node_kind(ctx.batch, child),
            Some(NodeKind::Method | NodeKind::Function)
        ) {
            continue;
        }
        if let Some(name) = string_prop(ctx.batch, child, "name") {
            names.push(name.to_owned());
        }
    }
    names
}

fn find_unbalanced_pair<'a>(names: &[String]) -> Option<(&'a str, &'a str, &'a str)> {
    for (a, b, lang) in PAIRS {
        let has_a = names.iter().any(|n| n == *a);
        let has_b = names.iter().any(|n| n == *b);
        if has_a && !has_b {
            return Some((a, b, lang));
        }
        if has_b && !has_a {
            return Some((b, a, lang));
        }
    }
    None
}
