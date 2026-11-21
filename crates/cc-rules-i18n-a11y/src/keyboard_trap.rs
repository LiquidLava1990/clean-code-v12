//! `cc.a11y.keyboard_trap` — focus trap without an escape route.
//!
//! Phase-5 STUB. Detection requires DOM-aware analysis: every keyboard
//! interaction handler in a focus trap must either route to the trap
//! escape (typically `Escape` keypress -> `closeModal` / `restoreFocus`)
//! or chain to a parent handler. Without an event-handler graph the
//! probe cannot distinguish a legitimate modal trap (Esc-closeable)
//! from a hostile one.
//!
//! TODO(future): wire DOM event-handler graph. Once the JSX lift
//! exposes `onKeyDown` / `onKeyUp` handlers as typed CPG nodes and the
//! call-graph resolver tracks escape-key routing, replace this stub
//! with an analysis that walks the focus-trap region and asserts every
//! handler chain ends in a known escape sink.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-15 probe R-A11Y-KEYBOARD-TRAP (Phase-5 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyboardTrapRule;

impl Rule for KeyboardTrapRule {
    fn rule_id(&self) -> &'static str {
        "cc.a11y.keyboard_trap"
    }
    fn category(&self) -> Category {
        Category::A11y
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "focus trap without an escape route (Phase-5 stub — no detection yet)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-5 stub. Detection requires a DOM event-handler graph
        // the frontend lift does not yet provide.
        Vec::new()
    }
}
