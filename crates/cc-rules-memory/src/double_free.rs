//! `cc.memory.double_free` — STUB.
//!
//! Double-free analysis is native-language-only (Rust unsafe blocks,
//! C/C++ via tree-sitter-c / tree-sitter-cpp). Phase-3 ships the rule
//! shell so the pack registry has the full five rules, but emission is
//! deferred until the Infer Pulse port lands.
//
// TODO(phase-4): wire an Infer Pulse-style interprocedural port.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-6 probe R-MEM-DF (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct DoubleFreeRule;

impl Rule for DoubleFreeRule {
    fn rule_id(&self) -> &'static str {
        "cc.memory.double_free"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Memory
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "double free in unsafe Rust / C / C++ (stub — Phase 4 wiring pending)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-4): wire Infer Pulse port for native double-free detection.
        Vec::new()
    }
}
