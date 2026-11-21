//! `cc.rot.bus_factor` — STUB.
//!
//! Detection requires git-blame author histograms across the file
//! (areas where a single author owns >N% of lines). Not available in
//! Phase 4.
//!
//! TODO(phase-5): wire git-blame author histograms.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-18 probe R-ROT-BUS-FACTOR (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct BusFactorRule;

impl Rule for BusFactorRule {
    fn rule_id(&self) -> &'static str {
        "cc.rot.bus_factor"
    }
    fn category(&self) -> Category {
        Category::Rot
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "single-author ownership concentration (Phase-4 stub; needs git blame)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire git-blame walker.
        Vec::new()
    }
}
