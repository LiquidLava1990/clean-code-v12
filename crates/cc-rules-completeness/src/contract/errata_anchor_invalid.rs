//! `cc.contract.errata_anchor_invalid` — comment containing
//! `errata: <ref>` whose `<ref>` looks like `path/to/file.ext:LINE`.
//!
//! Phase-2 status: regex-match only. File-existence verification via
//! the source table requires full repo enumeration which is out of
//! scope for the per-file Phase-2 RuleContext. The rule flags every
//! match for triage with a TODO.

use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.contract.errata_anchor_invalid`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrataAnchorInvalidRule;

impl Rule for ErrataAnchorInvalidRule {
    fn rule_id(&self) -> &'static str {
        "cc.contract.errata_anchor_invalid"
    }
    fn category(&self) -> Category {
        Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "errata reference uses positional anchor — content-anchored preferred"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = enclosing_file_path(ctx.batch, file.id) else {
                continue;
            };
            let bytes = ctx.source.get(&path);
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for snippet in find_positional_errata(text) {
                let loc = location_from_node(ctx.batch, file.id, path.clone());
                out.push(build_finding(CompletenessFindingBlueprint {
                    rule_id: "cc.contract.errata_anchor_invalid",
                    category: Category::Docs,
                    severity: Severity::Required,
                    confidence: Confidence::new(0.5),
                    location: loc,
                    headline: "errata uses positional anchor (`file:line`)".to_owned(),
                    explanation: "Positional anchors rot the moment a file is edited. \
                         Use a content-anchored snippet (a unique substring of the \
                         target line) so the reference survives renumbering."
                        .into(),
                    remediation: Remediation::SuggestedRewrite(
                        "Replace `file.py:123` with the literal source text being \
                         referenced (quoted, ≥ 8 chars)."
                            .into(),
                    ),
                    snippet,
                    weight: 1,
                }));
            }
        }
        out
    }
}

/// Naive scanner for `errata: <path>:<line>` patterns.
fn find_positional_errata(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(idx) = lower.find("errata") else {
            continue;
        };
        let tail = &line[idx..];
        if tail.contains(':') && tail.chars().any(|c| c.is_ascii_digit()) {
            out.push(tail.trim().to_owned());
        }
    }
    out
}
