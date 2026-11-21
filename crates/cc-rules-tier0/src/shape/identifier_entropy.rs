//! Tier-0 forever rule R-IDENTIFIER-ENTROPY.
//!
//! Flag identifiers (function / variable / class names) whose Shannon
//! entropy per character falls below [`MIN_BITS_PER_CHAR`] AND whose
//! length exceeds [`MIN_LENGTH`]. The length floor avoids flagging
//! `i`, `id`, `ok`, `err`, etc., which are short by convention.
//!
//! Catches `aaaaa`, `xxxxxx`, `foooooo`, `data1234`-style names that
//! pass naming-convention checks (the casing is right) but carry zero
//! semantic information. Sonar S100 and detekt's
//! `MagicNumberInName` are the spiritual predecessors; we generalise
//! to entropy.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Below this many bits per character, the identifier is mostly
/// repeats. Sonar S100 uses 1.5 bits as the canonical "low information"
/// floor; we adopt the same.
// TODO(W2): wire ctx.config thresholds
const MIN_BITS_PER_CHAR: f64 = 1.5;

/// Names at or below this length are exempt — `i`, `id`, `ok`, `err`,
/// `tmp`, `idx` are conventional even when entropy is technically low.
const MIN_LENGTH: usize = 4;

/// Tier-0 forever rule R-IDENTIFIER-ENTROPY.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentifierEntropyRule;

impl Rule for IdentifierEntropyRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.identifier_entropy"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "identifier carries less than 1.5 bits of entropy per character"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Class,
            NodeKind::Variable,
            NodeKind::Parameter,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_name(ctx, node.id, kind) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_name(ctx: &RuleContext<'_>, id: NodeId, kind: NodeKind) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if name.len() <= MIN_LENGTH || name.starts_with('_') {
        return None;
    }
    let bits = shannon_bits_per_char(name);
    if bits >= MIN_BITS_PER_CHAR {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    let kind_label = describe_kind(kind);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.identifier_entropy",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "{kind_label} `{name}` has low identifier entropy ({bits:.2} bits/char, threshold {MIN_BITS_PER_CHAR})"
        ),
        explanation: format!(
            "Low-entropy names like `{name}` carry no semantic content. \
             {bits:.2} bits/char is below the {MIN_BITS_PER_CHAR} floor; the name \
             is mostly repeats or a single-character pattern."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rename to a descriptive identifier that names the concept it represents \
             (e.g. `pending_invoices` over `xxxxx`)."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

const fn describe_kind(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Function => "function",
        NodeKind::Method => "method",
        NodeKind::Class => "type",
        NodeKind::Variable => "variable",
        NodeKind::Parameter => "parameter",
        _ => "identifier",
    }
}

/// Shannon entropy in bits per character over the byte stream of
/// `name`. Implemented over u8 (ASCII identifiers are the common case;
/// non-ASCII names are still scored, just as bytes).
fn shannon_bits_per_char(name: &str) -> f64 {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[*b as usize] = counts[*b as usize].saturating_add(1);
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        entropy -= p * p.log2();
    }
    entropy
}
