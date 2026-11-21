//! [`BuiltinArchitecturePack`] — registers the eight Family-20 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::circular_import::CircularImportRule;
use crate::cross_module_private_access::CrossModulePrivateAccessRule;
use crate::fan_in_outlier::FanInOutlierRule;
use crate::fan_out_outlier::FanOutOutlierRule;
use crate::god_module_imports::GodModuleImportsRule;
use crate::layer_violation::LayerViolationRule;
use crate::layer_violation_import::LayerViolationImportRule;
use crate::ownership_gap::OwnershipGapRule;

/// Built-in Family-20 [`RulePack`] — eight probes registered at boot.
///
/// Distinct `PACK_ID` keeps the registry separable from sibling packs
/// (`cc-builtin-bugs`, `cc-builtin-concurrency`, …).
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinArchitecturePack;

impl BuiltinArchitecturePack {
    /// Stable pack id.
    pub const PACK_ID: &'static str = "cc-builtin-architecture";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static LAYER_VIOLATION: LayerViolationRule = LayerViolationRule;
static CIRCULAR_IMPORT: CircularImportRule = CircularImportRule;
static FAN_IN_OUTLIER: FanInOutlierRule = FanInOutlierRule;
static FAN_OUT_OUTLIER: FanOutOutlierRule = FanOutOutlierRule;
static OWNERSHIP_GAP: OwnershipGapRule = OwnershipGapRule;
// Phase 10 probes (Batch L — multi-language cross-cutting).
static LAYER_VIOLATION_IMPORT: LayerViolationImportRule = LayerViolationImportRule;
static GOD_MODULE_IMPORTS: GodModuleImportsRule = GodModuleImportsRule;
static CROSS_MODULE_PRIVATE_ACCESS: CrossModulePrivateAccessRule = CrossModulePrivateAccessRule;

static RULES: &[&'static dyn Rule] = &[
    &LAYER_VIOLATION,
    &CIRCULAR_IMPORT,
    &FAN_IN_OUTLIER,
    &FAN_OUT_OUTLIER,
    &OWNERSHIP_GAP,
    &LAYER_VIOLATION_IMPORT,
    &GOD_MODULE_IMPORTS,
    &CROSS_MODULE_PRIVATE_ACCESS,
];

impl RulePack for BuiltinArchitecturePack {
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
