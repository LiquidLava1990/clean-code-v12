//! [`BuiltinDatabasePack`] — registers the six Family-10 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::json_blob_hellscape::JsonBlobHellscapeRule;
use crate::locking_migration::LockingMigrationRule;
use crate::missing_backfill::MissingBackfillRule;
use crate::missing_fk::MissingFkRule;
use crate::missing_index::MissingIndexRule;
use crate::select_star_hot::SelectStarHotRule;

/// Built-in Family-10 [`RulePack`] — six probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinDatabasePack;

impl BuiltinDatabasePack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-database";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static MISSING_INDEX: MissingIndexRule = MissingIndexRule;
static MISSING_FK: MissingFkRule = MissingFkRule;
static JSON_BLOB_HELLSCAPE: JsonBlobHellscapeRule = JsonBlobHellscapeRule;
static LOCKING_MIGRATION: LockingMigrationRule = LockingMigrationRule;
static MISSING_BACKFILL: MissingBackfillRule = MissingBackfillRule;
static SELECT_STAR_HOT: SelectStarHotRule = SelectStarHotRule;

static RULES: &[&'static dyn Rule] = &[
    &MISSING_INDEX,
    &MISSING_FK,
    &JSON_BLOB_HELLSCAPE,
    &LOCKING_MIGRATION,
    &MISSING_BACKFILL,
    &SELECT_STAR_HOT,
];

impl RulePack for BuiltinDatabasePack {
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
