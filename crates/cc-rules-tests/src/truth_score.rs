//! `cc.test.truth_score` — composite test-truth metric.
//!
//! Phase-4 STUB. The truth score fuses four signals — mutation
//! survival × flake rate × coverage × churn-weighted assertion
//! density — into a single `[0.0, 1.0]` per-file score. Each input
//! depends on a Phase-5 surface (mutation report, flake history,
//! coverage report, git churn). Until those land the rule is
//! registered for surface stability and silent at run time.
//
// TODO(phase-5): wire mutation × flake × cov × churn fusion. Steps:
//   1. The four feeders above land first
//      (`MutationSurvivors`, `FlakeHistory`, `LineCoverage`, churn).
//   2. ScoreEngine exposes a `truth_score(file)` helper that
//      multiplies (1 - mutation_survival) × (1 - flake_rate) ×
//      coverage × (1 / (1 + churn)).
//   3. This rule reads the per-file score, compares against
//      `config.test.min_truth_score` (default `0.7`), and fires for
//      every file below the floor.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-8 probe R-TEST-TRUTH-SCORE (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct TruthScoreRule;

impl Rule for TruthScoreRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.truth_score"
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
        "composite test-truth score below the configured floor"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-4 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
