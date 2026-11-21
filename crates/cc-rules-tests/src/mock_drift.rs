//! `cc.test.mock_drift` — mock signature drifts from the real impl
//! it stands in for.
//!
//! Phase-4 STUB. Detection requires whole-program signature comparison
//! between the symbol named in `Mock::new(MyTrait)` / `mock!(MyTrait)`
//! / `jest.mock("./module")` and the trait / class it claims to mock.
//! That data is not yet on the CPG — Phase-5 will add a
//! `MOCK_OF` edge plus a per-pack signature index.
//!
//! For now this rule is registered (so config / docs / surface stays
//! stable) and silently returns zero findings on every batch. It is
//! gated on [`crate::helpers::is_test_file_path`] for symmetry with
//! the live rules in this pack — when wired, it will only run on
//! files that ship mocks, never on production code.
//
// TODO(phase-5): wire whole-program signature comparison. Steps:
//   1. Frontend lifts `Mock<Trait>` / `mock!(Trait)` calls into a
//      typed `MockDecl` node carrying the mocked symbol's name.
//   2. Cross-batch index resolves the mocked symbol to its real impl.
//   3. Compare the mock's method set + parameter types + return types
//      with the real impl. Drift => finding.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-8 probe R-TEST-MOCK-DRIFT (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct MockDriftRule;

impl Rule for MockDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.mock_drift"
    }
    fn category(&self) -> Category {
        Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "mock signature drifts from the real impl it stands in for"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-4 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
