//! [`BuiltinTestsPack`] — registers the ten Family-8 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::assertion_free::AssertionFreeRule;
use crate::assertion_free_jest::AssertionFreeJestRule;
use crate::coverage_hole_on_diff::CoverageHoleOnDiffRule;
use crate::flaky::FlakyRule;
use crate::mock_drift::MockDriftRule;
use crate::mutation_survivor_density::MutationSurvivorDensityRule;
use crate::parallel_test_uses_shared_t::ParallelTestUsesSharedTRule;
use crate::testify_assertion_misuse::TestifyAssertionMisuseRule;
use crate::tests_the_mock::TestsTheMockRule;
use crate::truth_score::TruthScoreRule;

/// Built-in Family-8 [`RulePack`] — ten probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTestsPack;

impl BuiltinTestsPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-tests";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static ASSERTION_FREE: AssertionFreeRule = AssertionFreeRule;
static MOCK_DRIFT: MockDriftRule = MockDriftRule;
static FLAKY: FlakyRule = FlakyRule;
static COVERAGE_HOLE_ON_DIFF: CoverageHoleOnDiffRule = CoverageHoleOnDiffRule;
static TESTS_THE_MOCK: TestsTheMockRule = TestsTheMockRule;
static MUTATION_SURVIVOR_DENSITY: MutationSurvivorDensityRule = MutationSurvivorDensityRule;
static TRUTH_SCORE: TruthScoreRule = TruthScoreRule;

static PARALLEL_TEST_SHARED_T: ParallelTestUsesSharedTRule = ParallelTestUsesSharedTRule;
static TESTIFY_ASSERTION_MISUSE: TestifyAssertionMisuseRule = TestifyAssertionMisuseRule;
static ASSERTION_FREE_JEST: AssertionFreeJestRule = AssertionFreeJestRule;

static RULES: &[&'static dyn Rule] = &[
    &ASSERTION_FREE,
    &MOCK_DRIFT,
    &FLAKY,
    &COVERAGE_HOLE_ON_DIFF,
    &TESTS_THE_MOCK,
    &MUTATION_SURVIVOR_DENSITY,
    &TRUTH_SCORE,
    &PARALLEL_TEST_SHARED_T,
    &TESTIFY_ASSERTION_MISUSE,
    &ASSERTION_FREE_JEST,
];

impl RulePack for BuiltinTestsPack {
    fn pack_id(&self) -> &'static str {
        Self::PACK_ID
    }
    fn pack_semver(&self) -> &'static str {
        Self::PACK_SEMVER
    }
    fn kernel_api_min(&self) -> u32 {
        KERNEL_API_VERSION
    }
    fn kernel_api_max(&self) -> Option<u32> {
        None
    }
    fn rules(&self) -> &[&'static dyn Rule] {
        RULES
    }
}
