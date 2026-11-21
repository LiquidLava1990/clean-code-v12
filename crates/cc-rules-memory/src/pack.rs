//! [`BuiltinMemoryPack`] — registers the five Family-6 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::cache_unbounded::CacheUnboundedRule;
use crate::double_free::DoubleFreeRule;
use crate::event_loop_leak::EventLoopLeakRule;
use crate::unclosed_resource::UnclosedResourceRule;
use crate::use_after_free::UseAfterFreeRule;

/// Built-in Family-6 [`RulePack`] — five probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinMemoryPack;

impl BuiltinMemoryPack {
    /// Stable pack id. Distinct from every other `cc-builtin-*` so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-memory";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static UNCLOSED_RESOURCE: UnclosedResourceRule = UnclosedResourceRule;
static USE_AFTER_FREE: UseAfterFreeRule = UseAfterFreeRule;
static DOUBLE_FREE: DoubleFreeRule = DoubleFreeRule;
static EVENT_LOOP_LEAK: EventLoopLeakRule = EventLoopLeakRule;
static CACHE_UNBOUNDED: CacheUnboundedRule = CacheUnboundedRule;

static RULES: &[&'static dyn Rule] = &[
    &UNCLOSED_RESOURCE,
    &USE_AFTER_FREE,
    &DOUBLE_FREE,
    &EVENT_LOOP_LEAK,
    &CACHE_UNBOUNDED,
];

impl RulePack for BuiltinMemoryPack {
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
