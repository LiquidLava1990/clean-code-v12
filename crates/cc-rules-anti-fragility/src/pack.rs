//! [`BuiltinAntiFragilityPack`] — registers the four Family-23 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::network_in_test::NetworkInTestRule;
use crate::order_dependent::OrderDependentRule;
use crate::shared_global_state::SharedGlobalStateRule;
use crate::timing_assumption::TimingAssumptionRule;

/// Built-in Family-23 [`RulePack`] — four probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinAntiFragilityPack;

impl BuiltinAntiFragilityPack {
    /// Stable pack id. Distinct from every other built-in pack id so
    /// the registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-anti-fragility";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static TIMING_ASSUMPTION: TimingAssumptionRule = TimingAssumptionRule;
static NETWORK_IN_TEST: NetworkInTestRule = NetworkInTestRule;
static ORDER_DEPENDENT: OrderDependentRule = OrderDependentRule;
static SHARED_GLOBAL_STATE: SharedGlobalStateRule = SharedGlobalStateRule;

static RULES: &[&'static dyn Rule] = &[
    &TIMING_ASSUMPTION,
    &NETWORK_IN_TEST,
    &ORDER_DEPENDENT,
    &SHARED_GLOBAL_STATE,
];

impl RulePack for BuiltinAntiFragilityPack {
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
