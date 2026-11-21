//! `cc.docs.example_doesnt_compile` — STUB.
//!
//! Detection requires extracting fenced code blocks from doc comments
//! and compiling each one in a sub-process (the `mdbook test`
//! pattern). Phase 5 ships the rule registration only — Phase 6 wires
//! the sub-process executor.
//!
//! TODO(future): wire mdbook test pattern.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-16 probe R-DOCS-EXAMPLE-DOESNT-COMPILE (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ExampleDoesntCompileRule;

impl Rule for ExampleDoesntCompileRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.example_doesnt_compile"
    }
    fn category(&self) -> Category {
        Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "doc-comment example fails to compile (Phase-5 stub; needs sub-process)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(future): wire mdbook test pattern.
        Vec::new()
    }
}
