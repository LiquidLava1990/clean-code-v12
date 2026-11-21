//! `cc.test.coverage_hole_on_diff` — code added in the current diff
//! has no covering test.
//!
//! Phase-4 STUB. Detection requires (a) a git-diff handle so we know
//! which lines changed in the current branch / PR, and (b) a coverage
//! report mapping line → covering test. Neither is currently surfaced
//! on `RuleContext`. The rule is registered for surface stability.
//
// TODO(phase-5): wire diff-coverage. Steps:
//   1. CLI gains `--diff-base <ref>` and shells `git diff --unified=0`
//      to compute changed line ranges per file.
//   2. CLI gains `--coverage <path>` and parses a Cobertura / lcov /
//      go cover profile into a `LineCoverage` map.
//   3. Both surfaces hang off `RuleContext::project`. This rule
//      reads them, intersects "changed" with "uncovered", and fires
//      one finding per uncovered range.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-8 probe R-TEST-COVERAGE-HOLE-ON-DIFF (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct CoverageHoleOnDiffRule;

impl Rule for CoverageHoleOnDiffRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.coverage_hole_on_diff"
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
        "code added in the current diff has no covering test"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-4 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
