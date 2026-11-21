//! `cc.slop.llm_texture` — heuristic LLM-generated-prose detector.
//!
//! Phase-2 heuristic only. Two signals:
//!
//! 1. The function's docstring contains one or more canonical LLM
//!    "tells" (`Note that`, `Importantly,`, `It is worth noting`,
//!    `In essence,`, `However, it is important to`).
//! 2. The function body has more than three consecutive
//!    single-statement comments above single-statement lines (the
//!    "narrate every step" texture that LLMs lean into).
//!
//! Either signal alone suffices. We match the tells case-insensitively
//! at word boundaries to avoid false positives like an in-code string
//! `"in essence"`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, SlopFindingBlueprint,
};

const TELLS: &[&str] = &[
    "note that",
    "importantly,",
    "it is worth noting",
    "in essence,",
    "however, it is important to",
];

/// Family-1 rule R-SLOP-LLM-TEXTURE.
#[derive(Debug, Default, Clone, Copy)]
pub struct LlmTextureRule;

impl Rule for LlmTextureRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.llm_texture"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.88)
    }
    fn description(&self) -> &'static str {
        "function docstring or body has LLM-texture tells"
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
    let docstring = string_prop(ctx.batch, id, "docstring").unwrap_or("");
    let docstring_hit = docstring_has_tell(docstring);
    let body_hit = has_consecutive_comment_lines(ctx, id);
    if !docstring_hit && !body_hit {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    let cause = if docstring_hit {
        "docstring uses canonical LLM phrasing"
    } else {
        "body has more than three consecutive narration comments"
    };
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.llm_texture",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.88),
        location,
        headline: format!("`{name}` shows LLM-texture: {cause}"),
        explanation: format!(
            "Function `{name}` carries the prose texture typical of \
             unedited LLM output ({cause}). Hand-written code rarely uses \
             this register; replace with prose that explains the WHY of \
             the surrounding code, not the WHAT."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rewrite the docstring or comments to drop hedging phrasing \
             ('Note that', 'Importantly,', 'In essence,'). State the \
             contract directly. Delete narration comments that restate \
             the code beneath them."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

fn docstring_has_tell(docstring: &str) -> bool {
    let lower = docstring.to_ascii_lowercase();
    TELLS.iter().any(|tell| lower.contains(tell))
}

fn has_consecutive_comment_lines(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(path) = enclosing_file_path(ctx.batch, id) else {
        return false;
    };
    let bytes = ctx.source.get(&path);
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(range) = range_prop(ctx.batch, id, "range") else {
        return false;
    };
    let body = slice_for_range(source, range.start.offset, range.end.offset);
    count_consecutive_narration(body) > 3
}

fn slice_for_range(source: &str, start: u32, end: u32) -> &str {
    let s = (start as usize).min(source.len());
    let e = (end as usize).min(source.len()).max(s);
    source.get(s..e).unwrap_or("")
}

/// Count the longest run of (comment-line, code-line) pairs in `body`.
fn count_consecutive_narration(body: &str) -> u32 {
    let lines: Vec<&str> = body.lines().collect();
    let mut best: u32 = 0;
    let mut run: u32 = 0;
    let mut idx = 0;
    while idx + 1 < lines.len() {
        let comment = lines[idx].trim();
        let code = lines[idx + 1].trim();
        if is_comment_line(comment) && !code.is_empty() && !is_comment_line(code) {
            run += 1;
            best = best.max(run);
            idx += 2;
        } else {
            run = 0;
            idx += 1;
        }
    }
    best
}

fn is_comment_line(line: &str) -> bool {
    line.starts_with("//")
        || line.starts_with('#')
        || line.starts_with("///")
        || line.starts_with("/*")
        || line.starts_with('*')
}
