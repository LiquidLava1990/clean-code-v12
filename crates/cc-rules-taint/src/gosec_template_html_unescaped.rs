//! `cc.taint.gosec_template_html_unescaped` — Go
//! `template.HTML(userVar)` / `template.JS(userVar)` /
//! `template.URL(userVar)` / `template.HTMLAttr(userVar)` /
//! `template.JSStr(userVar)` / `template.CSS(userVar)` calls that
//! bypass `html/template`'s contextual auto-escaping.
//!
//! Mirrors [gosec G203] (`Use of unescaped data in HTML templates`).
//! These wrapper types (`type HTML string`, `type JS string`, etc.)
//! tell `html/template` "trust me, this is already safe in this
//! context" — passing user input through them is the canonical way
//! to introduce XSS in a Go web app.
//!
//! Detection: source-byte scan for `template.<Wrapper>(<arg>)` where
//! `arg` is *not* a string literal.
//!
//! [gosec G203]: https://github.com/securego/gosec/blob/master/rules/templates.go

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::_go_syntax::first_arg_slice;
use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

const WRAPPER_NEEDLES: &[&str] = &[
    "template.HTML(",
    "template.JS(",
    "template.URL(",
    "template.HTMLAttr(",
    "template.JSStr(",
    "template.CSS(",
];

/// Family-4 probe `cc.taint.gosec_template_html_unescaped`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecTemplateHtmlUnescapedRule;

impl Rule for GosecTemplateHtmlUnescapedRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.gosec_template_html_unescaped"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Go html/template wrapper used on a non-literal value (gosec G203)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_go_source(&path) {
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

fn is_go_source(path: &Utf8PathBuf) -> bool {
    let ext_ok = path.extension().map(str::to_ascii_lowercase).as_deref() == Some("go");
    if !ext_ok {
        return false;
    }
    !path
        .file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        for needle in matched_wrappers(line) {
            if !first_arg_is_string_literal(line, needle) {
                out.push(emit(path.clone(), idx + 1, line, needle));
            }
        }
    }
}

fn matched_wrappers(line: &str) -> Vec<&'static str> {
    WRAPPER_NEEDLES
        .iter()
        .copied()
        .filter(|n| line.contains(n))
        .collect()
}

fn first_arg_is_string_literal(line: &str, needle: &str) -> bool {
    let Some(pos) = line.find(needle) else {
        return true;
    };
    let after = &line[pos + needle.len()..];
    let arg = first_arg_slice(after);
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return true;
    }
    let first = trimmed.chars().next().unwrap_or(' ');
    let last = trimmed.chars().last().unwrap_or(' ');
    matches!((first, last), ('"', '"') | ('`', '`'))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, wrapper: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TaintFindingBlueprint {
        rule_id: "cc.taint.gosec_template_html_unescaped",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "`{}` bypasses html/template auto-escaping (gosec G203)",
            wrapper.trim_end_matches('('),
        ),
        explanation: "`html/template` chooses the right escape per \
             output context (HTML body, attribute, JS, URL, CSS). The \
             `template.HTML` / `template.JS` / `template.URL` / `*Attr` \
             / `*Str` / `CSS` wrappers tell the engine the value is \
             *already* safe for that context, suppressing escaping. \
             gosec G203 flags every wrapper applied to a non-literal \
             expression — the canonical XSS injection point in Go web \
             apps."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the wrapper and let `html/template` escape the value \
             contextually. If the value really is pre-sanitised, do the \
             sanitisation explicitly (`bluemonday`, allow-list HTML \
             policy) and document why the wrapper is correct here."
                .into(),
        ),
        snippet,
        weight: 7,
    })
}
