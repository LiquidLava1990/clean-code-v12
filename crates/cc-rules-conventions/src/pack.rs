//! [`BuiltinConventionsPack`] — registers the five Family-24 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::config_json_for_non_auth::ConfigJsonForNonAuthRule;
use crate::file_claim_bypass::FileClaimBypassRule;
use crate::module_missing_manifest::ModuleMissingManifestRule;
use crate::startup_py_exists::StartupPyExistsRule;
use crate::untyped_event::UntypedEventRule;

/// Built-in Family-24 [`RulePack`] — five probes registered at boot.
///
/// `R-ERR-ACTION`: registry rejection of this pack means the kernel
/// API drifted; bump `kernel_api_min` and re-vendor.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinConventionsPack;

impl BuiltinConventionsPack {
    /// Stable pack id. Distinct from every sibling builtin pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-conventions";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static CONFIG_JSON_FOR_NON_AUTH: ConfigJsonForNonAuthRule = ConfigJsonForNonAuthRule;
static STARTUP_PY_EXISTS: StartupPyExistsRule = StartupPyExistsRule;
static MODULE_MISSING_MANIFEST: ModuleMissingManifestRule = ModuleMissingManifestRule;
static UNTYPED_EVENT: UntypedEventRule = UntypedEventRule;
static FILE_CLAIM_BYPASS: FileClaimBypassRule = FileClaimBypassRule;

static RULES: &[&'static dyn Rule] = &[
    &CONFIG_JSON_FOR_NON_AUTH,
    &STARTUP_PY_EXISTS,
    &MODULE_MISSING_MANIFEST,
    &UNTYPED_EVENT,
    &FILE_CLAIM_BYPASS,
];

impl RulePack for BuiltinConventionsPack {
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
