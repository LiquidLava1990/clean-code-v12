//! [`BuiltinApiPack`] — registers the six Family-9 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::breaking_change_no_version::BreakingChangeNoVersionRule;
use crate::client_server_drift::ClientServerDriftRule;
use crate::errcode_collision::ErrCodeCollisionRule;
use crate::response_shape_drift::ResponseShapeDriftRule;
use crate::schema_vs_db_drift::SchemaVsDbDriftRule;
use crate::struct_tag_required::StructTagRequiredRule;

/// Built-in Family-9 [`RulePack`] — six probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinApiPack;

impl BuiltinApiPack {
    /// Stable pack id. Distinct from sibling Phase-4 packs so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-api";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static CLIENT_SERVER_DRIFT: ClientServerDriftRule = ClientServerDriftRule;
static BREAKING_CHANGE_NO_VERSION: BreakingChangeNoVersionRule = BreakingChangeNoVersionRule;
static SCHEMA_VS_DB_DRIFT: SchemaVsDbDriftRule = SchemaVsDbDriftRule;
static RESPONSE_SHAPE_DRIFT: ResponseShapeDriftRule = ResponseShapeDriftRule;

static STRUCT_TAG_REQUIRED: StructTagRequiredRule = StructTagRequiredRule;
static ERRCODE_COLLISION: ErrCodeCollisionRule = ErrCodeCollisionRule;

static RULES: &[&'static dyn Rule] = &[
    &CLIENT_SERVER_DRIFT,
    &BREAKING_CHANGE_NO_VERSION,
    &SCHEMA_VS_DB_DRIFT,
    &RESPONSE_SHAPE_DRIFT,
    &STRUCT_TAG_REQUIRED,
    &ERRCODE_COLLISION,
];

impl RulePack for BuiltinApiPack {
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
