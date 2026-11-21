//! `cc.test.private_helper_imported_into_test` — Phase-6 STUB.
//!
//! Detection requires a visibility cross-check: for every Import in a
//! test file, resolve the target symbol in the production source and
//! determine whether the resolution targets a `pub(crate)` / `pub(super)`
//! / module-local symbol that is NOT part of the public API. Per-batch
//! lift cannot see across files; we need the resolved call-graph from
//! `cc-cpg-store` plus the visibility metadata from each frontend's
//! lift pipeline.
//
// TODO(phase-7): wire visibility cross-check. Steps:
//   1. Each frontend lifts a `visibility` property on every exported
//      Function / Class / Variable (`pub`, `pub(crate)`, `private`,
//      `module`, `package`).
//   2. Persist the (module, name, visibility) triple in `cc-cpg-store`
//      under a new `symbol_visibility` table.
//   3. This rule walks every Import in a test file, resolves the
//      target via the store, and fires when visibility !=
//      `pub` / `public` / `export`.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-28 probe `cc.test.private_helper_imported_into_test` (Phase-6 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateHelperImportedIntoTestRule;

impl Rule for PrivateHelperImportedIntoTestRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.private_helper_imported_into_test"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "test imports a private helper — couples test to internal shape"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-6 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
