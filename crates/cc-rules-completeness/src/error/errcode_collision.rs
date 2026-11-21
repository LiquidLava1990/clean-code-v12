//! `cc.error.errcode_collision` — two distinct error classes share the
//! same `errcode` string. Severity: BLOCKER.
//!
//! Heuristic: scan every class body for `errcode = "..."` /
//! `ERRCODE = "..."` / `code: "..."`. Group by the literal string.
//! Flag every site whose group has > 1 class.

use std::collections::BTreeMap;

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_body_text, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.error.errcode_collision`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrcodeCollisionRule;

impl Rule for ErrcodeCollisionRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.errcode_collision"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "two error classes claim the same ErrCode"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let claims = collect_claims(ctx);
        emit_collisions(ctx, &claims)
    }
}

fn collect_claims(ctx: &RuleContext<'_>) -> BTreeMap<String, Vec<(NodeId, String)>> {
    let mut claims: BTreeMap<String, Vec<(NodeId, String)>> = BTreeMap::new();
    for class in nodes_of_kind(ctx.batch, NodeKind::Class) {
        let name = string_prop(ctx.batch, class.id, "name")
            .unwrap_or("")
            .to_owned();
        let body = function_body_text(ctx.batch, class.id, ctx.source).unwrap_or_default();
        for code in extract_errcodes(&body) {
            claims
                .entry(code)
                .or_default()
                .push((class.id, name.clone()));
        }
    }
    claims
}

fn emit_collisions(
    ctx: &RuleContext<'_>,
    claims: &BTreeMap<String, Vec<(NodeId, String)>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (code, sites) in claims {
        if sites.len() < 2 {
            continue;
        }
        for (id, name) in sites {
            if let Some(f) = build_collision(ctx, *id, name, code, sites.len()) {
                out.push(f);
            }
        }
    }
    out
}

fn build_collision(
    ctx: &RuleContext<'_>,
    id: NodeId,
    name: &str,
    code: &str,
    count: usize,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.error.errcode_collision",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("ErrCode `{code}` collides across {count} classes"),
        explanation: "Two distinct error classes that share an ErrCode break \
             dashboards, runbooks, and bug-history queries. ErrCodes must be \
             globally unique."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename one of the `{code}` claims to a unique value (e.g. `{code}_A` and \
             `{code}_B`) — class `{name}` is one of the colliders."
        )),
        snippet: format!("{name} :: {code}"),
        weight: 3,
    }))
}

/// Naive errcode extractor: looks for `errcode = "X"` / `ERRCODE: "X"`
/// / `code: "X"` patterns in the class body.
fn extract_errcodes(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if !is_errcode_line(trimmed) {
            continue;
        }
        if let Some(code) = extract_quoted(trimmed) {
            out.push(code);
        }
    }
    out
}

fn is_errcode_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("errcode") || lower.contains("err_code") || lower.starts_with("code")
}

fn extract_quoted(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let rest = &line[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}
