//! `cc.docs.dead_link` — STUB.
//!
//! Detection requires fetching every URL referenced by the docs and
//! observing 4xx / 5xx / DNS failure. Phase 5 ships the rule
//! registration only — Phase 6 wires the lychee-style HTTP fetcher.
//!
//! TODO(future): wire lychee port.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-16 probe R-DOCS-DEAD-LINK (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadLinkRule;

impl Rule for DeadLinkRule {
    fn rule_id(&self) -> &'static str {
        "cc.docs.dead_link"
    }
    fn category(&self) -> Category {
        Category::Docs
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "documentation URL is dead (Phase-5 stub; needs HTTP fetcher)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(future): wire lychee port.
        Vec::new()
    }
}
