//! Tier-0 forever rule R-LAMBDA-COMPLEXITY.
//!
//! Flag lambdas / arrow functions / closures whose bodies exceed
//! `MAX_STATEMENTS` top-level statements OR
//! `MAX_CYCLOMATIC` McCabe cyclomatic complexity. Detekt's
//! `LongLambda` rule defaults to ~10 statements; we adopt the same plus
//! a complexity ceiling of 4 (a single decision tree is fine; two
//! branches with a loop is not).
//!
//! "Lambda" here means a `Function` / `Method` AST node whose parent is
//! neither `File`, `Module`, nor `Class` — i.e. defined inside an
//! expression context. Frontends differ in how they label these (Rust
//! `|x| { … }`, TS `(x) => { … }`, Python `lambda x: …`, Go
//! `func(x) { … }` literals); the parent-context filter catches them
//! all uniformly.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_children, ast_parent, bool_prop, node_kind, nodes_of_kind, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold cited from detekt `LongLambda` (default 10 statements).
// TODO(W2): wire ctx.config thresholds
const MAX_STATEMENTS: u32 = 10;

/// Cyclomatic complexity ceiling for a lambda body. Cited as the
/// "single decision tree" line drawn by clippy's
/// `cognitive_complexity` lint when applied to closures (default 4).
// TODO(W2): wire ctx.config thresholds
const MAX_CYCLOMATIC: u32 = 4;

/// Tier-0 forever rule R-LAMBDA-COMPLEXITY.
#[derive(Debug, Default, Clone, Copy)]
pub struct LambdaComplexityRule;

impl Rule for LambdaComplexityRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.lambda_complexity"
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
        "lambda body exceeds 10 statements or cyclomatic 4"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if !is_lambda_context(ctx, node.id) {
                    continue;
                }
                if let Some(finding) = check_lambda(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

/// True when the function-kind node is a lambda / closure / arrow.
///
/// Heuristic: frontends label lambdas with one of three signals —
///
/// 1. The node carries an `is_lambda` / `is_closure` / `is_anonymous`
///    bool property set to `true`.
/// 2. The node has no `name` property, or the name matches one of
///    `<anonymous>` / `<lambda>` / `<closure>` / empty.
/// 3. The AST parent is an expression context (`Call` arg position,
///    assignment to `Variable`, etc.) — anything except top-level
///    containers (`File`, `Module`, `Class`) AND non-expression
///    structural nodes (`Block` is structural; methods in `impl` blocks
///    sit under a `Block`, so we exclude `Block` from "lambda context").
fn is_lambda_context(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if bool_prop(ctx.batch, id, "is_lambda").unwrap_or(false)
        || bool_prop(ctx.batch, id, "is_closure").unwrap_or(false)
        || bool_prop(ctx.batch, id, "is_anonymous").unwrap_or(false)
    {
        return true;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("");
    if name.is_empty() || matches!(name, "<anonymous>" | "<lambda>" | "<closure>" | "lambda") {
        return parent_is_expression_context(ctx, id);
    }
    false
}

fn parent_is_expression_context(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, id) else {
        return false;
    };
    let parent_kind = node_kind(ctx.batch, parent);
    matches!(
        parent_kind,
        Some(
            NodeKind::Call
                | NodeKind::Variable
                | NodeKind::Return
                | NodeKind::Write
                | NodeKind::Read
        )
    )
}

fn check_lambda(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let stmt_count = count_statements(ctx.batch, id);
    let cyclomatic = cyclomatic_score(ctx.batch, id);
    let stmt_violation = stmt_count > MAX_STATEMENTS;
    let cyc_violation = cyclomatic > MAX_CYCLOMATIC;
    if !stmt_violation && !cyc_violation {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<lambda>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = stmt_count
        .saturating_sub(MAX_STATEMENTS)
        .saturating_add(cyclomatic.saturating_sub(MAX_CYCLOMATIC));
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.lambda_complexity",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "lambda `{name}` body has {stmt_count} stmts, cyclomatic {cyclomatic} \
             (thresholds {MAX_STATEMENTS} / {MAX_CYCLOMATIC})"
        ),
        explanation: format!(
            "Lambdas are call-site sugar for short anonymous logic. `{name}` runs \
             {stmt_count} statements and {cyclomatic} cyclomatic — extract to a \
             named function so the call site reads as one verb."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Lift the lambda body into a named helper function; pass the helper \
             reference at the call site."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

fn count_statements(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    count_matching_descendants(batch, root, is_statement_kind)
}

fn cyclomatic_score(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    1u32.saturating_add(count_matching_descendants(batch, root, is_branch_kind))
}

/// Walk AST descendants of `root` and count those whose kind satisfies
/// `predicate`. Stops recursion at any nested `Function` / `Method`
/// boundary so closures don't bleed into the parent count.
fn count_matching_descendants(
    batch: &CpgWriteBatch,
    root: NodeId,
    predicate: fn(NodeKind) -> bool,
) -> u32 {
    let mut count: u32 = 0;
    for child in ast_children(batch, root) {
        let Some(kind) = node_kind(batch, child) else {
            continue;
        };
        if matches!(kind, NodeKind::Function | NodeKind::Method) {
            continue;
        }
        if predicate(kind) {
            count = count.saturating_add(1);
        }
        count = count.saturating_add(count_matching_descendants(batch, child, predicate));
    }
    count
}

const fn is_statement_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Variable
            | NodeKind::Branch
            | NodeKind::Loop
            | NodeKind::Try
            | NodeKind::Return
            | NodeKind::Call
            | NodeKind::Write
            | NodeKind::Async
    )
}

const fn is_branch_kind(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::Branch | NodeKind::Loop)
}
