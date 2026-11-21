//! [`BuiltinDeployPack`] — registers the four Family-13 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::big_bang_migration::BigBangMigrationRule;
use crate::missing_feature_flag::MissingFeatureFlagRule;
use crate::no_rollback_path::NoRollbackPathRule;
use crate::stale_flag::StaleFlagRule;

/// Built-in Family-13 [`RulePack`] — four probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinDeployPack;

impl BuiltinDeployPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-deploy";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static NO_ROLLBACK_PATH: NoRollbackPathRule = NoRollbackPathRule;
static BIG_BANG_MIGRATION: BigBangMigrationRule = BigBangMigrationRule;
static MISSING_FEATURE_FLAG: MissingFeatureFlagRule = MissingFeatureFlagRule;
static STALE_FLAG: StaleFlagRule = StaleFlagRule;

static RULES: &[&'static dyn Rule] = &[
    &NO_ROLLBACK_PATH,
    &BIG_BANG_MIGRATION,
    &MISSING_FEATURE_FLAG,
    &STALE_FLAG,
];

impl RulePack for BuiltinDeployPack {
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
