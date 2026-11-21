//! `cc.config.env_drift` — flag the same env var with different defaults
//! across multiple environment-specific config files.
//!
//! Phase-2 stub: returns an empty [`Vec`] until cross-batch reasoning
//! lands. The probe needs to compare values across e.g.
//! `config.dev.toml` and `config.prod.toml`, which the Phase-2 single-
//! batch contract does not support.
//!
//! TODO(phase-3): wire to fingerprint cross-file config drift index.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-19 probe R-ENV-DRIFT (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvDriftRule;

impl Rule for EnvDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.env_drift"
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
        "(stub) env var has divergent defaults across environment configs"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-3): wire to fingerprint cross-file config drift index.
        Vec::new()
    }
}
