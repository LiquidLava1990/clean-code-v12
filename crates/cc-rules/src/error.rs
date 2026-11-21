//! Errors raised by the `cc-rules` registry + runner.
//!
//! Every variant carries a *what* and a *how*: an actionable message
//! that names the offending input plus a concrete remediation. The
//! self-host gate (R-ERR-ACTION) requires this — adding a variant
//! without both halves is a regression.

use thiserror::Error;

/// Specialised result alias for registry operations.
pub type RegistryResult<T> = Result<T, RegistryError>;

/// Registry + runner error surface.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A pack declared a `kernel_api_min` newer than this kernel exposes.
    #[error(
        "pack '{pack_id}' requires kernel API >= {required} but this kernel exposes {available} \
         — upgrade cc-kernel to at least the API version listed in the pack manifest, \
         or downgrade the pack to one whose kernel_api_min <= {available}"
    )]
    KernelApiTooNew {
        /// Pack that failed registration.
        pack_id: &'static str,
        /// Minimum API the pack demands.
        required: u32,
        /// API version this kernel exposes.
        available: u32,
    },

    /// A pack declared a `kernel_api_max` older than this kernel exposes.
    #[error(
        "pack '{pack_id}' caps kernel API at {cap} but this kernel exposes {available} \
         — upgrade the pack to a release that supports kernel API {available}, \
         or pin cc-kernel to a version whose API <= {cap}"
    )]
    KernelApiTooOld {
        /// Pack that failed registration.
        pack_id: &'static str,
        /// Maximum API the pack accepts.
        cap: u32,
        /// API version this kernel exposes.
        available: u32,
    },

    /// Two packs registered the same rule id.
    #[error(
        "rule id '{rule_id}' is already registered by pack '{existing_pack}'; \
         pack '{incoming_pack}' attempted to re-register it \
         — rename one of the rules so each id is unique across all loaded packs, \
         or unregister the conflicting pack before registering the new one"
    )]
    DuplicateRuleId {
        /// Rule id that collided.
        rule_id: &'static str,
        /// Pack that owns the id today.
        existing_pack: &'static str,
        /// Pack attempting to re-register.
        incoming_pack: &'static str,
    },

    /// Two packs registered the same pack id.
    #[error(
        "pack id '{pack_id}' is already registered \
         — choose a unique pack_id (e.g. by appending a vendor prefix) \
         or unregister the existing pack before registering this one"
    )]
    DuplicatePackId {
        /// Pack id that collided.
        pack_id: &'static str,
    },
}
