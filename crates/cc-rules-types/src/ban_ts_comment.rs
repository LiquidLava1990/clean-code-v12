//! `cc.type.ban_ts_comment` — `// @ts-ignore` / `// @ts-nocheck` /
//! `// @ts-expect-error` directives without an inline description.
//!
//! Syntactic shadow of TypeScript ESLint's `ban-ts-comment`. The
//! sibling [`crate::unjustified_ignore`] probe handles a broader set of
//! markers across multiple languages and is satisfied by a number of
//! heuristic justifications (`because`, `bug 123`, `: …`); this probe
//! enforces the stricter `ban-ts-comment` policy on TS-specific
//! markers and demands at least 3 characters of trailing description
//! after the marker.
//!
//! Detected markers:
//!
//! - `// @ts-ignore`
//! - `// @ts-nocheck`
//! - `// @ts-expect-error`
//! - `// @ts-check`
//!
//! The marker is permitted only when followed (on the same line) by `:`
//! or `--` and a description of at least 3 non-whitespace characters.
//! TS-only.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-BAN-TS-COMMENT.
#[derive(Debug, Default, Clone, Copy)]
pub struct BanTsCommentRule;

const TS_MARKERS: &[&str] = &[
    "// @ts-ignore",
    "// @ts-nocheck",
    "// @ts-expect-error",
    "// @ts-check",
];

const MIN_DESCRIPTION_CHARS: usize = 3;

impl Rule for BanTsCommentRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.ban_ts_comment"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "TypeScript pragma directive missing inline description"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Comment) {
            if let Some(finding) = check_comment(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_comment(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, id)?;
    if !is_typescript(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_ts_extension(path.as_str()) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let text =
        string_prop(ctx.batch, id, "text").or_else(|| string_prop(ctx.batch, id, "value"))?;
    let marker = match_ts_marker(text)?;
    if has_inline_description(text, marker) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.ban_ts_comment",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`{marker}` without an inline description"),
        explanation: format!(
            "`{marker}` silences the TypeScript compiler. Without a written \
             reason on the same line the silencing becomes invisible \
             technical debt — the next reader has no way to tell whether \
             the warning was real, a known upstream bug, or a stale \
             relic of a long-fixed issue."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add a same-line description of at least {MIN_DESCRIPTION_CHARS} \
             characters after the marker, e.g. `{marker}: upstream issue \
             #1234 — fix tracked` or `{marker} -- DOM lib lacks declaration \
             for property X`."
        )),
        snippet: text.to_owned(),
        weight: 1,
    }))
}

fn match_ts_marker(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start();
    for marker in TS_MARKERS {
        if trimmed.starts_with(marker) {
            return Some(marker);
        }
    }
    None
}

fn has_inline_description(text: &str, marker: &str) -> bool {
    let trimmed = text.trim_start();
    let after = trimmed.get(marker.len()..).unwrap_or("");
    let line_end = after.find('\n').unwrap_or(after.len());
    let same_line = after.get(..line_end).unwrap_or("").trim();
    let cleaned = strip_separator(same_line);
    cleaned.chars().filter(|c| !c.is_whitespace()).count() >= MIN_DESCRIPTION_CHARS
}

fn strip_separator(text: &str) -> &str {
    if let Some(rest) = text.strip_prefix(':') {
        return rest.trim_start();
    }
    if let Some(rest) = text.strip_prefix("--") {
        return rest.trim_start();
    }
    text
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}
