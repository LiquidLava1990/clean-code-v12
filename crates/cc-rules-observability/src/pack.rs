//! [`BuiltinObservabilityPack`] — registers the six Family-11 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::high_cardinality_label::HighCardinalityLabelRule;
use crate::missing_metrics::MissingMetricsRule;
use crate::no_correlation_id::NoCorrelationIdRule;
use crate::pii_in_log::PiiInLogRule;
use crate::silent_catch::SilentCatchRule;
use crate::unstructured_log::UnstructuredLogRule;

/// Built-in Family-11 [`RulePack`] — six probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinObservabilityPack;

impl BuiltinObservabilityPack {
    /// Stable pack id. Distinct from sibling Phase-4 packs so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-observability";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static SILENT_CATCH: SilentCatchRule = SilentCatchRule;
static MISSING_METRICS: MissingMetricsRule = MissingMetricsRule;
static UNSTRUCTURED_LOG: UnstructuredLogRule = UnstructuredLogRule;
static HIGH_CARDINALITY_LABEL: HighCardinalityLabelRule = HighCardinalityLabelRule;
static NO_CORRELATION_ID: NoCorrelationIdRule = NoCorrelationIdRule;
static PII_IN_LOG: PiiInLogRule = PiiInLogRule;

static RULES: &[&'static dyn Rule] = &[
    &SILENT_CATCH,
    &MISSING_METRICS,
    &UNSTRUCTURED_LOG,
    &HIGH_CARDINALITY_LABEL,
    &NO_CORRELATION_ID,
    &PII_IN_LOG,
];

impl RulePack for BuiltinObservabilityPack {
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
