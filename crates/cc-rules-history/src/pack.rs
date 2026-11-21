//! [`BuiltinHistoryPack`] — registers the five Family-18 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::bus_factor::BusFactorRule;
use crate::churn_complexity_hotspot::ChurnComplexityHotspotRule;
use crate::parameter_creep::ParameterCreepRule;
use crate::partial_rewrites::PartialRewritesRule;
use crate::todo_aging::TodoAgingRule;

/// Built-in Family-18 [`RulePack`] — five probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinHistoryPack;

impl BuiltinHistoryPack {
    /// Stable pack id. Distinct from every other built-in pack.
    pub const PACK_ID: &'static str = "cc-builtin-history";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static CHURN_COMPLEXITY_HOTSPOT: ChurnComplexityHotspotRule = ChurnComplexityHotspotRule;
static PARAMETER_CREEP: ParameterCreepRule = ParameterCreepRule;
static PARTIAL_REWRITES: PartialRewritesRule = PartialRewritesRule;
static TODO_AGING: TodoAgingRule = TodoAgingRule;
static BUS_FACTOR: BusFactorRule = BusFactorRule;

static RULES: &[&'static dyn Rule] = &[
    &CHURN_COMPLEXITY_HOTSPOT,
    &PARAMETER_CREEP,
    &PARTIAL_REWRITES,
    &TODO_AGING,
    &BUS_FACTOR,
];

impl RulePack for BuiltinHistoryPack {
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
