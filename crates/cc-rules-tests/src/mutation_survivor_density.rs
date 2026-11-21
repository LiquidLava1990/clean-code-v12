//! `cc.test.mutation_survivor_density` — surviving mutants per kLoC
//! exceeds the configured ceiling.
//!
//! Phase-4 STUB. Detection requires a mutation-testing run
//! (`mutmut`, `cargo-mutants`, Stryker, `gremlins.js`, …) whose
//! output is parsed into a per-file `MutationSurvivors` map. Until
//! the kernel surfaces that, the rule registers and stays silent.
//
// TODO(phase-5): wire mutmut / cargo-mutants / Stryker output. Steps:
//   1. CLI gains `--mutation-report <path>` accepting a JSON shape
//      `{ "files": { "<rel>": { "survivors": u32, "kloc": f64 } } }`.
//   2. Loader hangs the parsed report off `RuleContext::project`.
//   3. This rule reads the per-file density, compares against
//      `config.mutation.max_survivors_per_kloc` (default `1.0`), and
//      fires for every file above the ceiling.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-8 probe R-TEST-MUTATION-SURVIVOR-DENSITY (Phase-4 stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct MutationSurvivorDensityRule;

impl Rule for MutationSurvivorDensityRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.mutation_survivor_density"
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
        "surviving mutants per kLoC exceeds the configured ceiling"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // Phase-4 stub. See module-level TODO for the wire-up plan.
        Vec::new()
    }
}
