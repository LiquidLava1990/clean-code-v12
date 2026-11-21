//! `cc.contract.invariant_unmonitored` — module declares
//! `INVARIANT: ...` in a docstring/comment but the body has no runtime
//! check (`assert`, `debug_assert`, `ensure!`, `if !... raise`).

use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.contract.invariant_unmonitored`.
#[derive(Debug, Default, Clone, Copy)]
pub struct InvariantUnmonitoredRule;

const INVARIANT_TAGS: &[&str] = &["INVARIANT:", "INVARIANT ", "Invariant:", "INV-"];
const RUNTIME_GUARDS: &[&str] = &[
    "assert!",
    "assert(",
    "debug_assert",
    "ensure!",
    "raise ",
    "panic!",
    "if !",
];

impl Rule for InvariantUnmonitoredRule {
    fn rule_id(&self) -> &'static str {
        "cc.contract.invariant_unmonitored"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "module declares an invariant but has no runtime guard"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in nodes_of_kind(ctx.batch, NodeKind::File) {
            if let Some(f) = check_file(ctx, file.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_file(ctx: &RuleContext<'_>, file_id: cc_cpg::NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, file_id)?;
    let bytes = ctx.source.get(&path);
    let text = std::str::from_utf8(bytes).ok()?;
    if !INVARIANT_TAGS.iter().any(|t| text.contains(t)) {
        return None;
    }
    if RUNTIME_GUARDS.iter().any(|g| text.contains(g)) {
        return None;
    }
    let location = location_from_node(ctx.batch, file_id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.contract.invariant_unmonitored",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: "module declares an invariant without a runtime guard".to_owned(),
        explanation: "Invariants in comments decay silently. Pair every `INVARIANT:` \
             marker with a `debug_assert!` / `ensure!` / `assert!` so the contract is \
             tested in CI."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add a runtime check (`assert!` / `ensure!`) at the function or constructor \
             that establishes the invariant."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
