//! `cc.api.client_server_drift` — STUB.
//!
//! Detection requires comparing TypeScript request/response types on
//! the client side against the server-side handler return shapes. That
//! comparison is whole-program: the client batch and the server batch
//! land in two different parse units, and a single-batch heuristic
//! would misfire on legitimate per-language idioms. The probe is
//! registered so the pack count is stable, but unconditionally returns
//! an empty [`Vec`].
//!
//! TODO(phase-5): wire client-server schema cross-reference once the
//! persistent CPG store can hold both sides simultaneously.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-9 probe R-API-CLIENT-SERVER-DRIFT (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientServerDriftRule;

impl Rule for ClientServerDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.client_server_drift"
    }
    fn category(&self) -> Category {
        Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "client TS types disagree with server response shape (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire client-server schema cross-reference.
        Vec::new()
    }
}
