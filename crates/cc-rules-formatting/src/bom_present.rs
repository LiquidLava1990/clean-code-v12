//! `cc.fmt.bom_present` — flag files that begin with the UTF-8 BOM
//! (`EF BB BF`).
//!
//! The UTF-8 byte-order mark is legal but pointless: UTF-8 has no byte
//! order and many tools (Python ≤ 3.0 `runpy`, shell `#!` interpreters,
//! gofumpt, rustfmt) treat the BOM as data and break.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// UTF-8 byte-order-mark sequence.
pub const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Family-26 probe R-FMT-BOM.
#[derive(Debug, Default, Clone, Copy)]
pub struct BomPresentRule;

impl Rule for BomPresentRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.bom_present"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.99)
    }
    fn description(&self) -> &'static str {
        "file starts with the UTF-8 byte-order mark"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            if !bytes.starts_with(UTF8_BOM) {
                continue;
            }
            out.push(emit(path));
        }
        out
    }
}

fn emit(path: camino::Utf8PathBuf) -> Finding {
    let location = location_for_file(path, 1);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.bom_present",
        severity: Severity::Nit,
        confidence: Confidence::new(0.99),
        location,
        headline: String::from("file starts with the UTF-8 BOM"),
        explanation: String::from(
            "The first three bytes are `EF BB BF` (the UTF-8 byte-order \
             mark). UTF-8 has no byte order, so the BOM is redundant — \
             and several tools (POSIX shells reading shebang lines, \
             rustfmt, gofumpt, older Python interpreters) misinterpret \
             it as data and fail to parse the file.",
        ),
        remediation: Remediation::SuggestedRewrite(
            "Strip the BOM with `sed -i '1s/^\\xEF\\xBB\\xBF//' <file>` \
             or your editor's 'save without BOM' setting."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
