//! `cc.type.protocol_drift` — STUB.
//!
//! Detects implementations that diverge from a declared
//! Protocol / interface / trait. Phase-3 simplification: the rule
//! returns an empty Vec because resolving "implements" / "implements
//! Protocol" / "trait impl" relationships requires whole-program
//! resolution that has not been wired yet.
//!
//! TODO(phase-4): wire whole-program protocol resolution. Required
//! inputs:
//!
//! - Per-language symbol resolver populating `CG_OVERRIDES` edges
//!   between an `impl` block / class / module and the corresponding
//!   declaration node.
//! - Member-set comparison: walk the declaration's child Function /
//!   Method nodes, walk the implementation's, and emit a finding for
//!   every member missing on the impl side or for every signature whose
//!   parameter / return shape diverges.
//! - Per-language signature normaliser so Python's
//!   `def foo(self, x: int)` and the corresponding Protocol's
//!   `def foo(self, x: int) -> None` compare as compatible.
//!
//! When that infrastructure lands, this stub becomes a real probe and
//! `BuiltinTypesPack::rules()` already exposes it — no kernel re-wiring
//! is required.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-22 probe R-TYPE-PROTOCOL-DRIFT (STUB).
///
/// Always returns `Vec::new()` until Phase 4 wiring lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProtocolDriftRule;

impl Rule for ProtocolDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.protocol_drift"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "implementation diverges from declared Protocol / interface / trait (stub — Phase 4)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-4): wire whole-program protocol resolution.
        Vec::new()
    }
}
