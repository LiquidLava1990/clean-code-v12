//! Probe-pack and kernel ABI versioning.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::StaticStr;

/// Kernel ABI version exposed to probe packs.
///
/// Backed by [`Cow<'static, str>`] so probe-pack constants can pass
/// `&'static str` literals (zero-alloc) while deserialised findings
/// own their string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KernelVersion(pub StaticStr);

impl KernelVersion {
    /// Compile-time current kernel version, sourced from `CARGO_PKG_VERSION`.
    #[must_use]
    pub const fn current() -> Self {
        Self(Cow::Borrowed(env!("CARGO_PKG_VERSION")))
    }

    /// Construct from a static literal.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

/// Probe-pack identity + the kernel ABI window it requires.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProbeVersion {
    /// Pack identifier, e.g. `"cc-tier0"`.
    pub pack_id: StaticStr,
    /// Pack semver, e.g. `"1.2.3"`.
    pub pack_semver: StaticStr,
    /// Minimum kernel ABI required by this pack.
    pub kernel_api_min: u32,
    /// Maximum kernel ABI accepted (open-ended when `None`).
    pub kernel_api_max: Option<u32>,
}

impl ProbeVersion {
    /// Convenience constructor accepting `&'static str` literals.
    #[must_use]
    pub const fn new(
        pack_id: &'static str,
        pack_semver: &'static str,
        kernel_api_min: u32,
        kernel_api_max: Option<u32>,
    ) -> Self {
        Self {
            pack_id: Cow::Borrowed(pack_id),
            pack_semver: Cow::Borrowed(pack_semver),
            kernel_api_min,
            kernel_api_max,
        }
    }
}
