//! `cc.api.errcode_collision` — same `ErrCode` literal string used by
//! more than one error site.
//!
//! Error codes are load-bearing strings — telemetry
//! routes, dashboards filter, and runbooks key off them. Re-using the
//! same code from two different sites means a downstream consumer
//! cannot tell which failure mode actually fired without reading source.
//! One canonical name per concept is the rule; collisions are the
//! multi-site analogue of a naming clash.
//!
//! Phase-8 single-file implementation: walk every Call to
//! `ErrCode::new(...)`, `ErrCode("...")`, or `errcode!(...)` (the three
//! common `ErrCode` constructor shapes) within the current
//! file. Group by literal value. If a value is constructed by more than
//! one distinct enclosing function — fire.
//!
//! Cross-file aggregation (the requested true scope) requires kernel
//! state spanning multiple `RuleContext` invocations, which the Phase-8
//! kernel does not expose; the conservative single-file shadow
//! captures the most common collision pattern (errors duplicated
//! within the same module's body).
//!
//! Confidence 0.95 — when matched, the collision is unambiguous.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, is_test_file_path, ApiFindingBlueprint};

/// Family-9 probe R-API-ERRCODE-COLLISION.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrCodeCollisionRule;

/// Source extensions worth scanning. Rust, Python, and TypeScript /
/// JavaScript are the languages where `ErrCode` constructors appear.
const SUPPORTED_EXTS: &[&str] = &["rs", "py", "ts", "tsx", "js", "jsx"];

/// Constructor needles. Every match captures the string-literal
/// argument that follows.
const CTOR_NEEDLES: &[&str] = &[
    "ErrCode::new(\"",
    "ErrCode::new('",
    "ErrCode(\"",
    "ErrCode('",
    "errcode!(\"",
    "errcode!('",
    "ERR_CODE(\"",
];

impl Rule for ErrCodeCollisionRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.errcode_collision"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "ErrCode literal value used by more than one site in the same file"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_ext(&path) {
                continue;
            }
            if is_test_file_path(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_supported_ext(path: &Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| SUPPORTED_EXTS.iter().any(|e| *e == ext))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let occurrences = collect_occurrences(text);
    let collisions = group_collisions(occurrences);
    for collision in collisions {
        out.push(emit(path.clone(), &collision));
    }
}

#[derive(Debug, Clone)]
struct Occurrence {
    line: usize,
    enclosing_fn: String,
    code: String,
    snippet: String,
}

fn collect_occurrences(text: &str) -> Vec<Occurrence> {
    let mut out = Vec::new();
    let mut current_fn = String::new();
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(name) = parse_enclosing_fn_header(line) {
            current_fn = name.to_owned();
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for needle in CTOR_NEEDLES {
            let Some(idx) = line.find(needle) else {
                continue;
            };
            let after = &line[idx + needle.len()..];
            let close_quote = needle.chars().last().unwrap_or('"');
            let Some(end) = after.find(close_quote) else {
                continue;
            };
            let code = after[..end].to_owned();
            if code.is_empty() {
                continue;
            }
            out.push(Occurrence {
                line: line_idx + 1,
                enclosing_fn: current_fn.clone(),
                code,
                snippet: line.trim().chars().take(180).collect(),
            });
        }
    }
    out
}

fn parse_enclosing_fn_header(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix("fn ") {
        return parse_simple_name(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("pub fn ") {
        return parse_simple_name(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("def ") {
        return parse_simple_name(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("async fn ") {
        return parse_simple_name(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("function ") {
        return parse_simple_name(rest);
    }
    None
}

fn parse_simple_name(rest: &str) -> Option<&str> {
    let end = rest
        .find(|c: char| c == '(' || c == '<' || c == ':' || c.is_whitespace())
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[derive(Debug)]
struct Collision {
    code: String,
    sites: Vec<Occurrence>,
}

fn group_collisions(occurrences: Vec<Occurrence>) -> Vec<Collision> {
    let mut by_code: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    for occ in occurrences {
        by_code.entry(occ.code.clone()).or_default().push(occ);
    }
    let mut out = Vec::new();
    for (code, sites) in by_code {
        if !is_collision(&sites) {
            continue;
        }
        out.push(Collision { code, sites });
    }
    out
}

fn is_collision(sites: &[Occurrence]) -> bool {
    if sites.len() < 2 {
        return false;
    }
    let first_fn = &sites[0].enclosing_fn;
    sites.iter().any(|s| &s.enclosing_fn != first_fn)
}

/// Inputs to [`build_collision_finding`] — grouped to keep `emit` lean
/// and to make the relationship between the path and the collision
/// explicit at the call site.
struct CollisionInput<'a> {
    path: Utf8PathBuf,
    collision: &'a Collision,
}

fn emit(path: Utf8PathBuf, collision: &Collision) -> Finding {
    build_collision_finding(CollisionInput { path, collision })
}

fn build_collision_finding(input: CollisionInput<'_>) -> Finding {
    let CollisionInput { path, collision } = input;
    let first = &collision.sites[0];
    let pos = Position::new(first.line as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(first.enclosing_fn.clone()),
    };
    let other_lines = format_other_sites(&collision.sites);
    build_finding(ApiFindingBlueprint {
        rule_id: "cc.api.errcode_collision",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "ErrCode `{}` is used by {} distinct sites in this file",
            collision.code,
            collision.sites.len()
        ),
        explanation: format!(
            "ErrCode `{}` is constructed by more than one enclosing \
             function in this file (other sites: {}). Telemetry, \
             dashboards, and runbooks key off the literal code, so two \
             different failure modes that share a code are \
             indistinguishable downstream. Keep one canonical code \
             per failure mode.",
            collision.code, other_lines
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pick one site to keep the existing code and rename the other \
             to an unambiguous variant (e.g. `<DOMAIN>_<VERB>_<REASON>` — \
             `AUTH_TOKEN_EXPIRED` vs `AUTH_TOKEN_MALFORMED`). Add the new \
             code to your central `ErrCode` registry so the enum \
             stays the single source of truth."
                .into(),
        ),
        snippet: first.snippet.clone(),
        weight: 3,
    })
}

/// Render every collision site after the first as a comma-separated
/// `"line N (function)"` list for the finding explanation.
fn format_other_sites(sites: &[Occurrence]) -> String {
    sites
        .iter()
        .skip(1)
        .map(|s| {
            let scope = if s.enclosing_fn.is_empty() {
                "<top-level>"
            } else {
                s.enclosing_fn.as_str()
            };
            format!("line {} ({})", s.line, scope)
        })
        .collect::<Vec<_>>()
        .join(", ")
}
