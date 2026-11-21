//! [`BuiltinCompliancePack`] — registers the four Family-21 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::audit_log_gap::AuditLogGapRule;
use crate::gdpr_pattern::GdprPatternRule;
use crate::license_violation::LicenseViolationRule;
use crate::pii_handling::PiiHandlingRule;

/// Built-in Family-21 [`RulePack`] — four probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinCompliancePack;

impl BuiltinCompliancePack {
    /// Stable pack id. Distinct from sibling packs so the registry can
    /// host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-compliance";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static PII_HANDLING: PiiHandlingRule = PiiHandlingRule;
static GDPR_PATTERN: GdprPatternRule = GdprPatternRule;
static AUDIT_LOG_GAP: AuditLogGapRule = AuditLogGapRule;
static LICENSE_VIOLATION: LicenseViolationRule = LicenseViolationRule;

static RULES: &[&'static dyn Rule] = &[
    &PII_HANDLING,
    &GDPR_PATTERN,
    &AUDIT_LOG_GAP,
    &LICENSE_VIOLATION,
];

impl RulePack for BuiltinCompliancePack {
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
