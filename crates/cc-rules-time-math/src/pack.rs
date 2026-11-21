//! [`BuiltinTimeMathPack`] — registers the five Family-14 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::dst_unsafe::DstUnsafeRule;
use crate::float_equality::FloatEqualityRule;
use crate::leap_second::LeapSecondRule;
use crate::money_in_float::MoneyInFloatRule;
use crate::naive_datetime::NaiveDatetimeRule;

/// Built-in Family-14 [`RulePack`] — five probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTimeMathPack;

impl BuiltinTimeMathPack {
    /// Stable pack id. Distinct from sibling packs so the registry can
    /// host all of them side-by-side without colliding.
    pub const PACK_ID: &'static str = "cc-builtin-time-math";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static NAIVE_DATETIME: NaiveDatetimeRule = NaiveDatetimeRule;
static FLOAT_EQUALITY: FloatEqualityRule = FloatEqualityRule;
static MONEY_IN_FLOAT: MoneyInFloatRule = MoneyInFloatRule;
static DST_UNSAFE: DstUnsafeRule = DstUnsafeRule;
static LEAP_SECOND: LeapSecondRule = LeapSecondRule;

static RULES: &[&'static dyn Rule] = &[
    &NAIVE_DATETIME,
    &FLOAT_EQUALITY,
    &MONEY_IN_FLOAT,
    &DST_UNSAFE,
    &LEAP_SECOND,
];

impl RulePack for BuiltinTimeMathPack {
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
