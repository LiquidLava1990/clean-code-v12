//! `cc.fragile.shared_global_state` — tests mutating module-level state.
//!
//! Heuristic: in test files, walk every [`NodeKind::Write`] whose
//! `target` resolves to a top-level (Module / File parent) [`Variable`]
//! [`NodeKind`]. Cross-test mutation of shared globals is the
//! second-most-common test-flake pattern after timing — Test B sees
//! whatever Test A left behind.
//!
//! Two complementary signals fire this rule:
//!
//! - **AST-shape**: the Write's enclosing function (the nearest
//!   `Function` / `Method` / `Class` ancestor) is itself a direct child
//!   of a `Module` / `File`, *and* the Write's target name appears as a
//!   top-level Variable in the same file. This is the canonical
//!   "module-level state mutated from inside a test" shape.
//! - **Property hint**: frontends that lift a `scope` / `target_scope` /
//!   `is_global` property on the Write node trigger when the value
//!   says `module` / `global` / `true`.
//!
//! Either signal is enough. Non-test files are silent — production
//! mutation of module-level state belongs to other rules.

use std::collections::BTreeSet;

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, bool_prop, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    AntiFragilityFindingBlueprint,
};

/// Family-23 probe `cc.fragile.shared_global_state`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SharedGlobalStateRule;

impl Rule for SharedGlobalStateRule {
    fn rule_id(&self) -> &'static str {
        "cc.fragile.shared_global_state"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Fragile
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "test mutates module-level / global state shared across tests"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let module_vars = collect_module_level_var_names(ctx);
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node, &module_vars) {
                out.push(finding);
            }
        }
        out
    }
}

fn collect_module_level_var_names(ctx: &RuleContext<'_>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
        if !parent_is_module_or_file(ctx, node.id) {
            continue;
        }
        if let Some(name) = string_prop(ctx.batch, node.id, "name") {
            names.insert(name.to_owned());
        }
    }
    names
}

fn check_write(
    ctx: &RuleContext<'_>,
    write: &Node,
    module_vars: &BTreeSet<String>,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target")?;
    if !is_module_level_target(ctx, write.id, target, module_vars) {
        return None;
    }
    let location = location_from_node(ctx.batch, write.id, path);
    Some(build_finding(AntiFragilityFindingBlueprint {
        rule_id: "cc.fragile.shared_global_state",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("test mutates module-level state `{target}`"),
        explanation: format!(
            "`{target}` is declared at module scope, so every test in this \
             file shares the same instance. The first test to mutate it \
             leaks state into every subsequent test — flake risk + \
             order-dependence + parallel-runner failures."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Move the state into a per-test fixture / setup / `beforeEach`, \
             or wrap the value in a thread-local that resets on teardown. \
             Treat module-level mutables as configuration, not test \
             scratch space."
                .into(),
        ),
        snippet: target.to_owned(),
        weight: 3,
    }))
}

fn is_module_level_target(
    ctx: &RuleContext<'_>,
    write_id: NodeId,
    target: &str,
    module_vars: &BTreeSet<String>,
) -> bool {
    if write_target_is_global_by_property(ctx, write_id) {
        return true;
    }
    module_vars.contains(target)
}

fn write_target_is_global_by_property(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if let Some(scope) =
        string_prop(ctx.batch, id, "target_scope").or_else(|| string_prop(ctx.batch, id, "scope"))
    {
        let lower = scope.to_ascii_lowercase();
        if lower == "module" || lower == "global" || lower == "file" {
            return true;
        }
    }
    bool_prop(ctx.batch, id, "is_global").unwrap_or(false)
}

fn parent_is_module_or_file(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    matches!(
        ast_parent(ctx.batch, id).and_then(|p| node_kind(ctx.batch, p)),
        Some(NodeKind::File | NodeKind::Module)
    )
}
