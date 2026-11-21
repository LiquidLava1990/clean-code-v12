//! `cc.ops.unbounded_memory` — accumulator without cap.
//!
//! **Phase-4 STUB.** The detection axis (top-level container that
//! `push`/`append` is called on inside a loop, with no `clear` /
//! `truncate` / `pop` in scope) is fully covered by Family 6's
//! `cc.memory.cache_unbounded`. Re-implementing it here would
//! double-flag the same accumulators.
//!
//! TODO(phase-5): de-dup with `cc.memory.cache_unbounded` once
//! severity escalation is configurable. The intended Phase-5 contract
//! is that this probe stays silent when Family 6 already fires on the
//! same `Variable` and only reports when Family 6 does not see the
//! container (e.g. a function-local `Vec` that never escapes).
//!
//! Until then this rule registers (so the pack ships seven probes) and
//! returns an empty [`Vec`] on every batch — never a false positive
//! against a signal it cannot disambiguate from Family 6.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-12 probe `cc.ops.unbounded_memory` (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct UnboundedMemoryRule;

impl Rule for UnboundedMemoryRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.unbounded_memory"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "accumulator without cap (Phase-4 stub — defers to cc.memory.cache_unbounded)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): de-dup with cc.memory.cache_unbounded once
        // severity escalation is configurable.
        Vec::new()
    }
}
