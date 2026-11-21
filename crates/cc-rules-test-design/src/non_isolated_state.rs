//! `cc.test.non_isolated_state` — Phase-6 STUB.
//!
//! Test mutates a `static` / module-level Variable. The detection
//! pattern is identical to [`cc.fragile.shared_global_state`] in
//! `cc-rules-anti-fragility`. Rather than duplicate the body and risk
//! synonym-churn (S5: ONE name per concept), Family-28 registers the
//! rule_id for surface stability and defers to anti-fragility's
//! existing implementation.
//
// TODO(phase-7): merge with `cc.fragile.shared_global_state` once
// severity escalation per-pack is configurable. The plan:
//   1. `cc-config` gains a `severity_override` table keyed by `(rule_id,
//      pack_id)` so two packs can share detection but ship different
//      severity defaults.
//   2. This rule routes through that table — anti-fragility keeps
//      `Required` / 0.8 confidence, Family-28 raises to `Required` /
//      0.85 because test isolation is the headline concern.
//   3. Or: make this rule a thin alias that delegates the run() body
//      to the canonical implementation while preserving its own
//      rule_id for the registry (one detection, two reporting surfaces).

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-28 probe `cc.test.non_isolated_state` (Phase-6 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct NonIsolatedStateRule;

impl Rule for NonIsolatedStateRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.non_isolated_state"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test mutates a static / module-level variable — non-isolated state"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-6 stub. Defers to `cc.fragile.shared_global_state` — see
        // the module-level TODO for the merge plan.
        Vec::new()
    }
}
