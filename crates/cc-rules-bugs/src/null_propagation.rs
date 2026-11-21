//! `cc.bug.null_propagation` — Optional/Nullable value flowing into a
//! non-Optional sink without an unwrap-check.
//!
//! Phase-3 heuristic: enumerate [`NodeKind::Variable`] writes whose
//! initialiser callee text matches a known nullable producer
//! (Python `dict.get`, `re.search`, `re.match`, `os.environ.get`,
//! Rust `ok` / `as_ref` adapters, TS `Map.prototype.get`, ...) and whose
//! `unwrap_marker` property is not set by the frontend. Every such
//! variable is flagged as a candidate Optional-into-typed-sink leak.
//!
//! Because Phase-1 frontends do not yet emit `PDG_DATA` edges that
//! distinguish "x.method after x = maybe" from "x = maybe; match x",
//! we conservatively raise `Severity::Blocker` at a capped
//! `Confidence::new(0.55)`. PDG-aware tightening lives in Phase 4.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, BugFindingBlueprint,
};

/// Family-3 probe R-NULL-PROP.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullPropagationRule;

/// Callee substrings that conventionally return an Optional / Result /
/// nullable value. Substring match — covers Python (`.get(`, `re.search`),
/// Rust (`.ok()`, `find(`), JS/TS (`Map.get`, `find`), and Go (`os.LookupEnv`).
const NULLABLE_PRODUCERS: &[&str] = &[
    ".get(",
    ".find(",
    ".first(",
    ".last(",
    "re.search",
    "re.match",
    "os.environ.get",
    "os.LookupEnv",
    "Map.prototype.get",
    "HashMap::get",
    "BTreeMap::get",
    ".ok()",
    ".as_ref()",
    ".checked_",
];

impl Rule for NullPropagationRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.null_propagation"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.55)
    }
    fn description(&self) -> &'static str {
        "Optional / nullable value flows into a sink without unwrap-check"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_write(ctx: &RuleContext<'_>, write: NodeId) -> Option<Finding> {
    let initializer = string_prop(ctx.batch, write, "initializer")?;
    if !looks_nullable(initializer) {
        return None;
    }
    if has_unwrap_check(ctx, write) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, write)?;
    if is_test_file_path(&path) {
        return None;
    }
    let target = string_prop(ctx.batch, write, "target").unwrap_or("<binding>");
    let location = location_from_node(ctx.batch, write, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.null_propagation",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.55),
        location,
        headline: format!("`{target}` may hold a nullable value used without unwrap"),
        explanation: format!(
            "`{target}` is bound to the result of `{initializer}`, which can \
             return None / null / Err. Using `{target}` directly without a \
             `match`, `?`, `if let`, `unwrap_or`, or `??` guard risks a \
             NoneType / NullPointerException / unwrap panic at runtime."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Match / `?` / `if let Some(..)` the optional, or supply a default \
             via `unwrap_or` / `??` / `or_else` before passing the value to a \
             non-optional sink."
                .into(),
        ),
        snippet: initializer.to_owned(),
        weight: 4,
    }))
}

fn looks_nullable(initializer: &str) -> bool {
    NULLABLE_PRODUCERS
        .iter()
        .any(|needle| initializer.contains(needle))
}

fn has_unwrap_check(ctx: &RuleContext<'_>, write: NodeId) -> bool {
    if string_prop(ctx.batch, write, "unwrap_marker").is_some() {
        return true;
    }
    let Some(initializer) = string_prop(ctx.batch, write, "initializer") else {
        return false;
    };
    initializer.contains("unwrap_or")
        || initializer.contains('?')
        || initializer.contains("if let")
        || initializer.contains("match ")
        || initializer.contains(".expect(")
        || initializer.contains(" or ")
}
