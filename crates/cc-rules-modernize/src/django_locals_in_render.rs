//! `cc.modernize.django_locals_in_render` — Django
//! `render(request, 'tpl.html', locals())` is a footgun: it leaks every
//! local binding into the template namespace, including loop counters,
//! intermediate computations, and (worst) raw model querysets a
//! template author might not be expected to render safely.
//!
//! Mirrors ruff `DJ012` family (django-locals-in-render-context).
//!
//! Phase-10 detector: scan every `.py` file once for `render(...)`
//! calls whose argument list mentions `locals()` (positional or `=`).
//!
//! Severity: `Required`. Confidence 0.95 — the call shape is concrete
//! and the only false positive is a custom helper named `render` that
//! happens to accept `locals()`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.django_locals_in_render`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DjangoLocalsInRenderRule;

const RENDER_CALLEES: &[&str] = &[
    "render(",
    "shortcuts.render(",
    "django.shortcuts.render(",
    "render_to_response(",
];

impl Rule for DjangoLocalsInRenderRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.django_locals_in_render"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Django `render(..., locals())` leaks every local binding into the template"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
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

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (line_idx, line) in text.lines().enumerate() {
        if line_uses_locals_in_render(line) {
            out.push(emit(path.clone(), line_idx + 1, line));
        }
    }
}

fn line_uses_locals_in_render(line: &str) -> bool {
    if !line_contains_render_call(line) {
        return false;
    }
    line.contains("locals()")
}

fn line_contains_render_call(line: &str) -> bool {
    RENDER_CALLEES.iter().any(|callee| {
        line.find(callee)
            .is_some_and(|idx| !is_token_continuation(line, idx))
    })
}

fn is_token_continuation(line: &str, idx: usize) -> bool {
    if idx == 0 {
        return false;
    }
    let prev = line.as_bytes()[idx - 1];
    prev.is_ascii_alphanumeric() || prev == b'_'
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.django_locals_in_render",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`render(..., locals())` leaks every local binding into the template".into(),
        explanation: "`locals()` returns the entire local symbol table — \
             loop counters, intermediate computations, raw querysets the \
             template author probably never meant to render. Adding a \
             new helper variable in the view silently becomes a new \
             template variable. Worse, future readers cannot see what \
             keys the template depends on without scanning the whole \
             function for assignments."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass an explicit context dict listing exactly the keys the \
             template needs: \
             `render(request, 'tpl.html', {'user': user, 'orders': orders})`. \
             For larger contexts, build the dict in a `dict(...)` call or \
             a typed dataclass to make the contract reviewable."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
