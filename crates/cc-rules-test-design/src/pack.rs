//! [`BuiltinTestDesignPack`] — registers the fifteen Family-28 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::assertion_count_zero::AssertionCountZeroRule;
use crate::disabled_test::DisabledTestRule;
use crate::flaky_iteration::FlakyIterationRule;
use crate::gigantic_test_function::GiganticTestFunctionRule;
use crate::no_negative_case::NoNegativeCaseRule;
use crate::non_isolated_state::NonIsolatedStateRule;
use crate::private_helper_imported_into_test::PrivateHelperImportedIntoTestRule;
use crate::pt_assert_in_finally::PtAssertInFinallyRule;
use crate::pt_fixture_returns_value::PtFixtureReturnsValueRule;
use crate::pt_missing_test_classname_prefix::PtMissingTestClassnamePrefixRule;
use crate::pt_parametrize_no_kwargs::PtParametrizeNoKwargsRule;
use crate::pt_raises_simple_block::PtRaisesSimpleBlockRule;
use crate::shared_setup_in_assertion::SharedSetupInAssertionRule;
use crate::test_imports_test_module::TestImportsTestModuleRule;
use crate::unconditional_assert_true::UnconditionalAssertTrueRule;

/// Built-in Family-28 [`RulePack`] — fifteen probes registered at boot
/// (Phase 6 ten + Phase 11 pytest PT-family five).
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTestDesignPack;

impl BuiltinTestDesignPack {
    /// Stable pack id. Distinct from every other built-in pack.
    pub const PACK_ID: &'static str = "cc-builtin-test-design";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static UNCONDITIONAL_ASSERT_TRUE: UnconditionalAssertTrueRule = UnconditionalAssertTrueRule;
static DISABLED_TEST: DisabledTestRule = DisabledTestRule;
static SHARED_SETUP_IN_ASSERTION: SharedSetupInAssertionRule = SharedSetupInAssertionRule;
static FLAKY_ITERATION: FlakyIterationRule = FlakyIterationRule;
static NO_NEGATIVE_CASE: NoNegativeCaseRule = NoNegativeCaseRule;
static ASSERTION_COUNT_ZERO: AssertionCountZeroRule = AssertionCountZeroRule;
static PRIVATE_HELPER_IMPORTED_INTO_TEST: PrivateHelperImportedIntoTestRule =
    PrivateHelperImportedIntoTestRule;
static NON_ISOLATED_STATE: NonIsolatedStateRule = NonIsolatedStateRule;
static TEST_IMPORTS_TEST_MODULE: TestImportsTestModuleRule = TestImportsTestModuleRule;
static GIGANTIC_TEST_FUNCTION: GiganticTestFunctionRule = GiganticTestFunctionRule;

// Phase 11 — pytest PT-family long-tail.
static PT_FIXTURE_RETURNS_VALUE: PtFixtureReturnsValueRule = PtFixtureReturnsValueRule;
static PT_PARAMETRIZE_NO_KWARGS: PtParametrizeNoKwargsRule = PtParametrizeNoKwargsRule;
static PT_RAISES_SIMPLE_BLOCK: PtRaisesSimpleBlockRule = PtRaisesSimpleBlockRule;
static PT_ASSERT_IN_FINALLY: PtAssertInFinallyRule = PtAssertInFinallyRule;
static PT_MISSING_TEST_CLASSNAME_PREFIX: PtMissingTestClassnamePrefixRule =
    PtMissingTestClassnamePrefixRule;

static RULES: &[&'static dyn Rule] = &[
    &UNCONDITIONAL_ASSERT_TRUE,
    &DISABLED_TEST,
    &SHARED_SETUP_IN_ASSERTION,
    &FLAKY_ITERATION,
    &NO_NEGATIVE_CASE,
    &ASSERTION_COUNT_ZERO,
    &PRIVATE_HELPER_IMPORTED_INTO_TEST,
    &NON_ISOLATED_STATE,
    &TEST_IMPORTS_TEST_MODULE,
    &GIGANTIC_TEST_FUNCTION,
    // Phase 11 — pytest PT-family.
    &PT_FIXTURE_RETURNS_VALUE,
    &PT_PARAMETRIZE_NO_KWARGS,
    &PT_RAISES_SIMPLE_BLOCK,
    &PT_ASSERT_IN_FINALLY,
    &PT_MISSING_TEST_CLASSNAME_PREFIX,
];

impl RulePack for BuiltinTestDesignPack {
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
