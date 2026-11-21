//! `cc.shape.no_inheritance` — flag any `Class` node that extends another
//! class. Composition over inheritance is a forever rule.

use cc_cpg::{NodeKind, Value};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Tier-0 forever rule R-INHERIT.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoInheritanceRule;

impl Rule for NoInheritanceRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.no_inheritance"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "class extends another class — prefer composition over inheritance"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        nodes_of_kind(ctx.batch, NodeKind::Class)
            .filter(|node| has_extends(node))
            .filter_map(|node| {
                let path = enclosing_file_path(ctx.batch, node.id)?;
                let name = string_prop(ctx.batch, node.id, "name").unwrap_or("<anonymous>");
                let location = location_from_node(ctx.batch, node.id, path);
                Some(build_finding(Tier0FindingBlueprint {
                    rule_id: "cc.shape.no_inheritance",
                    category: Category::Shape,
                    severity: Severity::Required,
                    confidence: Confidence::certain(),
                    location,
                    headline: format!("class `{name}` extends another class"),
                    explanation: format!(
                        "Inheritance couples implementations. Class `{name}` declares \
                         a superclass; Tier-0 forbids inheritance — use composition."
                    ),
                    remediation: Remediation::SuggestedRewrite(
                        "Replace inheritance with composition: hold the would-be parent as a \
                         field and forward methods explicitly."
                            .into(),
                    ),
                    snippet: String::new(),
                    weight: 1,
                }))
            })
            .collect()
    }
}

fn has_extends(node: &cc_cpg::Node) -> bool {
    if let Some(value) = node.prop("extends") {
        return match value {
            Value::Bool(b) => *b,
            Value::String(s) => !s.is_empty(),
            Value::NodeRef(_) => true,
            Value::NodeList(list) => !list.is_empty(),
            _ => true,
        };
    }
    matches!(node.prop("superclasses"), Some(Value::NodeList(list)) if !list.is_empty())
}
