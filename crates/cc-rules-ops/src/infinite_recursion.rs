//! `cc.ops.infinite_recursion` — path-sensitive depth check.
//!
//! **Phase-4 STUB.** A correct detector needs `PDG_DATA` flow to prove
//! that no caller path leads to a base-case return. The CG_CALLS edge
//! shows that `f` calls itself; only data-flow shows whether that
//! recursive call is guarded by an early-return on a depth-bounded
//! parameter.
//!
//! TODO(phase-5): wire path-sensitive depth analysis. The intended
//! Phase-5 contract is to walk every function with a self-edge in the
//! call graph, locate the recursive call sites, and check that at
//! least one enclosing branch is gated on a parameter / iteration
//! variable that the recursive call shrinks.
//!
//! Until then this rule registers (so the pack ships seven probes) and
//! returns an empty [`Vec`] on every batch — never a false positive
//! against a signal it cannot see.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-12 probe `cc.ops.infinite_recursion` (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct InfiniteRecursionRule;

impl Rule for InfiniteRecursionRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.infinite_recursion"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "self-recursive function with no apparent base case (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire path-sensitive depth analysis.
        Vec::new()
    }
}
