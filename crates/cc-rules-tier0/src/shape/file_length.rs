//! `cc.shape.file_length` — flag files whose logical LOC exceeds the
//! per-repo threshold (default 1500).

use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, location_from_node, logical_line_count, Tier0FindingBlueprint,
};

/// Phase-1 default threshold per `docs/design/TIER_0_ALGORITHMS.md`.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_LOC: u32 = 1500;

/// Tier-0 forever rule R-FILE-LEN.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileLengthRule;

impl Rule for FileLengthRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.file_length"
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
        "file logical LOC exceeds threshold (default 1500)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        nodes_of_kind(ctx.batch, NodeKind::File)
            .filter_map(|node| {
                let path_str = string_prop(ctx.batch, node.id, "path")?;
                let path = camino::Utf8PathBuf::from(path_str);
                let bytes = ctx.source.get(path.as_path());
                if bytes.is_empty() {
                    tracing::debug!(
                        target: "cc_rules_tier0::file_length",
                        path = %path,
                        "source bytes empty; skipping file"
                    );
                    return None;
                }
                let loc = logical_line_count(bytes);
                if loc <= DEFAULT_MAX_LOC {
                    return None;
                }
                let weight = (loc - DEFAULT_MAX_LOC) / 100 + 1;
                let location = location_from_node(ctx.batch, node.id, path.clone());
                let headline = format!("file `{path}` is {loc} LOC (threshold {DEFAULT_MAX_LOC})");
                let explanation = format!(
                    "God-files hide architecture. `{path}` runs {loc} logical lines; \
                     the Tier-0 ceiling is {DEFAULT_MAX_LOC}."
                );
                Some(build_finding(Tier0FindingBlueprint {
                    rule_id: "cc.shape.file_length",
                    category: Category::Shape,
                    severity: Severity::Blocker,
                    confidence: Confidence::certain(),
                    location,
                    headline,
                    explanation,
                    remediation: Remediation::SuggestedRewrite(
                        "Split by responsibility into sibling modules; keep each file < 1500 LOC."
                            .into(),
                    ),
                    snippet: String::new(),
                    weight,
                }))
            })
            .collect()
    }
}
