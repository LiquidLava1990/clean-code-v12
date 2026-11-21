//! `cc.shape.fn_length` — flag functions whose logical LOC exceeds the
//! per-repo threshold (default 80).
//!
//! Threshold rationale: 50 is the Tier-0 craftsmanship aspiration but
//! over-fires on real Python codebases where module-level handlers
//! (FastAPI / Flask routes, asyncio entry points, scrapers) routinely
//! land at 50–80 logical lines. PEP 8 sets no length limit; ruff's
//! [`PLR0915`](https://docs.astral.sh/ruff/rules/too-many-statements/)
//! statement-count rule defaults to 50 statements (≈80–100 logical
//! lines); Google's Python style guide tolerates ~40 LOC but explicitly
//! permits longer when the function is "obvious". 80 LOC keeps the
//! ceiling on god-functions while ditching the noise floor.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, location_from_node, logical_line_count,
    snippet_from_bytes, Tier0FindingBlueprint,
};

/// Default threshold — see module docs for rationale.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_LOC: u32 = 80;

/// Tier-0 forever rule R-FN-LEN.
#[derive(Debug, Default, Clone, Copy)]
pub struct FnLengthRule;

impl Rule for FnLengthRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.fn_length"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "function logical LOC exceeds threshold (default 80)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let range = range_prop(ctx.batch, id, "range")?;
    let path = enclosing_file_path(ctx.batch, id)?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        tracing::debug!(
            target: "cc_rules_tier0::fn_length",
            path = %path,
            "source bytes empty; skipping function"
        );
        return None;
    }
    let snippet_bytes = byte_window(bytes, range.start.offset, range.end.offset);
    let loc = logical_line_count(snippet_bytes);
    if loc <= DEFAULT_MAX_LOC {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let weight = (loc - DEFAULT_MAX_LOC).saturating_mul(2);
    let location = location_from_node(ctx.batch, id, path);
    let snippet = snippet_from_bytes(bytes, range.start.offset, range.end.offset);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.fn_length",
        category: Category::Shape,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: format!("function `{name}` is {loc} LOC (threshold {DEFAULT_MAX_LOC})"),
        explanation: format!(
            "Long functions hide responsibilities. Function `{name}` runs {loc} \
             logical lines; the Tier-0 ceiling is {DEFAULT_MAX_LOC}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract sub-functions, each with one responsibility; aim well below 80 LOC.".into(),
        ),
        snippet,
        weight,
    }))
}
