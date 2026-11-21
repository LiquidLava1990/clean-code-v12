//! [`BuiltinCiPack`] — registers the five Family-17 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::flaky_test_history::FlakyTestHistoryRule;
use crate::hook_bypass_in_history::HookBypassInHistoryRule;
use crate::lockfile_uncommitted::LockfileUncommittedRule;
use crate::missing_step::MissingStepRule;
use crate::slow_test::SlowTestRule;

/// Built-in Family-17 [`RulePack`] — five probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinCiPack;

impl BuiltinCiPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-ci";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static FLAKY_TEST_HISTORY: FlakyTestHistoryRule = FlakyTestHistoryRule;
static SLOW_TEST: SlowTestRule = SlowTestRule;
static MISSING_STEP: MissingStepRule = MissingStepRule;
static LOCKFILE_UNCOMMITTED: LockfileUncommittedRule = LockfileUncommittedRule;
static HOOK_BYPASS_IN_HISTORY: HookBypassInHistoryRule = HookBypassInHistoryRule;

static RULES: &[&'static dyn Rule] = &[
    &FLAKY_TEST_HISTORY,
    &SLOW_TEST,
    &MISSING_STEP,
    &LOCKFILE_UNCOMMITTED,
    &HOOK_BYPASS_IN_HISTORY,
];

impl RulePack for BuiltinCiPack {
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
