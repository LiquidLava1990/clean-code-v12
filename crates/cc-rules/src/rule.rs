//! The [`Rule`] + [`RulePack`] traits — the contract every probe and
//! every probe pack implements.

use cc_finding::{Category, Confidence, Finding, Severity};

use crate::context::RuleContext;

/// Kernel ABI version exposed to probe packs.
///
/// Bumped whenever a breaking change lands in the [`Rule`] /
/// [`RuleContext`] / [`RulePack`] surface. Packs declare the API
/// window they support via [`RulePack::kernel_api_min`] +
/// [`RulePack::kernel_api_max`]; the registry refuses packs outside
/// the window.
pub const KERNEL_API_VERSION: u32 = 1;

/// The contract every Clean-Code-V12 probe implements.
///
/// Implementations are expected to be:
///
/// - **Pure** — given the same `ctx`, produce the same findings.
/// - **Allocation-conservative** — probes run on every changed file in
///   pre-commit mode; allocate per-finding, not per-node.
/// - **Panic-free in the happy path** — the runner does catch panics
///   (see [`crate::run_rule`]), but a panicking rule emits a Meta
///   finding and is reported as a probe bug.
pub trait Rule: Send + Sync + 'static {
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`. Must match the
    /// canonical taxonomy in `cc-config::registry::RULE_REGISTRY`.
    fn rule_id(&self) -> &'static str;

    /// Top-level [`Category`] for this rule.
    fn category(&self) -> Category;

    /// Severity stamped on emitted findings unless overridden by config.
    fn default_severity(&self) -> Severity;

    /// Calibrated default confidence. Rules that lower confidence on a
    /// per-finding basis should override [`Confidence`] when building
    /// the finding, not here.
    fn default_confidence(&self) -> Confidence;

    /// One-line human description, displayed in `cc check --rules`.
    fn description(&self) -> &'static str;

    /// Run the probe and return its findings. Empty vec = clean.
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding>;
}

/// A bundled, versioned set of [`Rule`]s.
///
/// Packs are the unit of distribution. The built-in Tier-0 forever
/// rules ship as `cc-builtin` (see [`crate::BuiltinPack`]); third-party
/// families ship as OCI artifacts on `ghcr.io` and are loaded by the
/// kernel via dlopen-equivalent in later phases.
pub trait RulePack: Send + Sync {
    /// Pack identifier, e.g. `"cc-builtin"`. Must be unique across all
    /// loaded packs in a single registry.
    fn pack_id(&self) -> &'static str;

    /// Pack semver string.
    fn pack_semver(&self) -> &'static str;

    /// Minimum kernel API version this pack requires. The registry
    /// rejects the pack if the running kernel's
    /// [`KERNEL_API_VERSION`] is lower.
    fn kernel_api_min(&self) -> u32;

    /// Optional maximum kernel API version this pack accepts.
    /// `None` means open-ended; `Some(n)` means the pack refuses any
    /// kernel above `n` until a new release is cut.
    fn kernel_api_max(&self) -> Option<u32>;

    /// The flat list of rules this pack ships.
    fn rules(&self) -> &[&'static dyn Rule];
}
