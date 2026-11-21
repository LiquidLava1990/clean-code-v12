//! `cc.config.dead_config_key` — flag YAML/TOML/JSON config keys that
//! are declared but never read in source.
//!
//! Phase-2 stub: returns an empty [`Vec`] until the Phase-3
//! fingerprint extension wires a config-graph that lets a probe reason
//! about config files alongside source files in the same batch.
//!
//! TODO(phase-3): wire to fingerprint config-graph.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-19 probe R-DEAD-CONFIG-KEY (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadConfigKeyRule;

impl Rule for DeadConfigKeyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.dead_config_key"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "(stub) top-level config key declared but never read"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-3): wire to fingerprint config-graph.
        Vec::new()
    }
}
