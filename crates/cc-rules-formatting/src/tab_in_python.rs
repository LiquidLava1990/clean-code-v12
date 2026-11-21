//! `cc.fmt.tab_in_python` — flag Python files that use tab indentation.
//!
//! PEP 8 mandates four-space indentation. A `*.py` file with any
//! tab-indented line will silently break in editors with tab width != 4
//! and is rejected by ruff (`W191`) / black / pylint by default.
//!
//! Severity: [`Severity::Nit`]. Test fixtures are skipped.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Family-26 probe R-FMT-TAB-IN-PYTHON.
#[derive(Debug, Default, Clone, Copy)]
pub struct TabInPythonRule;

impl Rule for TabInPythonRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.tab_in_python"
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
        "Python file uses tab indentation (PEP 8 requires spaces)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            if path.extension() != Some("py") {
                continue;
            }
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if let Some(lineno) = first_tab_indented_line(text) {
                out.push(emit(path, lineno));
            }
        }
        out
    }
}

fn first_tab_indented_line(text: &str) -> Option<u32> {
    for (idx, raw) in text.lines().enumerate() {
        if raw.starts_with('\t') {
            let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
            return Some(lineno);
        }
    }
    None
}

fn emit(path: camino::Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path, lineno);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.tab_in_python",
        severity: Severity::Nit,
        confidence: Confidence::new(0.99),
        location,
        headline: format!("Python file uses tab indentation (first hit on line {lineno})"),
        explanation: format!(
            "PEP 8 requires four-space indentation in Python source. \
             Line {lineno} is indented with a tab, which renders \
             differently in every editor whose tab width is not 4 and \
             is rejected by ruff (W191), black, and most CI lint passes."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Run `python -c \"import sys; sys.stdout.write(open('<file>').read().expandtabs(4))\"` \
             or your editor's 'convert indentation' command."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
