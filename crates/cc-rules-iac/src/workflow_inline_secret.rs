//! `cc.iac.workflow_inline_secret` — Phase-6 STUB.
//!
//! Detecting hardcoded credentials inside `.github/workflows/*.yml` is
//! already covered by `cc.config.secret_in_code` from `cc-rules-secrets`
//! (Family 19). Re-running the same regex pack here would just
//! double-emit findings. The rule is registered for namespace
//! reservation; emission is deferred to the secrets pack.
//!
//! TODO(phase-7): merge with `cc.config.secret_in_code` once severity
//! escalation lands so workflow-level hits can ladder up.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-29 probe R-IAC-WORKFLOW-INLINE-SECRET (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkflowInlineSecretRule;

impl Rule for WorkflowInlineSecretRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.workflow_inline_secret"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "stub — defers to `cc.config.secret_in_code` (Family 19)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        Vec::new()
    }
}
