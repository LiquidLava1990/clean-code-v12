//! `cc.modernize.sync_in_async_runtime` — Go `sync.Mutex` `Lock` /
//! `Unlock` calls inside a function whose enclosing scope spawns a
//! goroutine.
//!
//! Phase-6 stub: the present `cc-frontend-go` lift does not yet expose
//! the goroutine-context property our heuristic needs (we want a
//! `spawned_in_goroutine: bool` on `Function` nodes or a
//! `goroutine_ancestor` edge). Until that lands the rule walks the
//! batch and returns no findings.
//!
//! Severity: `Nit` (heuristic-grade by design).
//!
//! TODO(phase-7): wire the goroutine-context signal once
//! `cc_frontend_go` surfaces a stable `spawned_in_goroutine` /
//! `goroutine_ancestor` property.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-26 probe `cc.modernize.sync_in_async_runtime`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyncInAsyncRuntimeRule;

impl Rule for SyncInAsyncRuntimeRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.sync_in_async_runtime"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.4)
    }
    fn description(&self) -> &'static str {
        "Go sync.Mutex inside goroutine context (stub — phase-7 wiring)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-7): wire goroutine_ancestor signal from cc-frontend-go.
        Vec::new()
    }
}
