//! `cc.bug.html_url_javascript` — `href="javascript:..."` literal.
//!
//! `javascript:`-scheme URLs in HTML attributes (or JSX / template
//! strings that lower to HTML attributes) execute arbitrary script in
//! the page origin when the user clicks the link. The pattern is a
//! reliable XSS sink whether the literal sits in source HTML, in a
//! template, or in JSX.
//!
//! OSS source: SonarSource S5247 (`Disabling auto-escaping ... is
//! security-sensitive`) + SonarJS `no-javascript-url` rule.
//!
//! Phase-8 source-byte heuristic: scan `.html` / `.htm` / `.svg` /
//! `.jsx` / `.tsx` / `.vue` / `.svelte` / `.ts` / `.tsx` / `.js`
//! files for the literal substrings `href="javascript:` /
//! `href='javascript:` / `href={\`javascript:` plus the same patterns
//! for `src=`. Confidence 0.95 — every observed positive in the wild
//! is a true XSS.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-HTML-URL-JAVASCRIPT.
#[derive(Debug, Default, Clone, Copy)]
pub struct HtmlUrlJavascriptRule;

const SUPPORTED_EXTS: &[&str] = &[
    "html", "htm", "xhtml", "svg", "vue", "svelte", "jsx", "tsx", "ts", "js", "mjs", "cjs",
];

/// Substrings that uniquely identify an attribute-style `javascript:`
/// URL. Keep tight — any single needle produces a finding.
const JAVASCRIPT_URL_NEEDLES: &[&str] = &[
    "href=\"javascript:",
    "href='javascript:",
    "href=`javascript:",
    "href={\"javascript:",
    "href={'javascript:",
    "src=\"javascript:",
    "src='javascript:",
    "src=`javascript:",
    "formaction=\"javascript:",
    "formaction='javascript:",
];

impl Rule for HtmlUrlJavascriptRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.html_url_javascript"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "javascript:-scheme URL in href / src is an XSS sink"
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
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
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
    for (line_idx, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let trimmed = lower.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("<!--") {
            continue;
        }
        if let Some(needle) = JAVASCRIPT_URL_NEEDLES.iter().find(|n| lower.contains(*n)) {
            out.push(emit(path.clone(), line_idx + 1, line, needle));
        }
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.html_url_javascript",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`javascript:` URL in href / src is an XSS sink".into(),
        explanation: format!(
            "Found `{needle}...` in this file. Browsers execute the URL \
             body as script in the page origin when the link is clicked, \
             so any user-controlled fragment turns into reflected XSS. \
             Even when the URL is hard-coded, it normalises link \
             behaviour to 'sometimes runs script', which makes audit \
             trails noisy and CSP exemptions creep in over time."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `javascript:`-scheme URLs with a real target plus \
             a click handler attached in code (`onClick={fn}` / \
             `addEventListener`). For inert anchors use `href=\"#\"` \
             with `event.preventDefault()`."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
