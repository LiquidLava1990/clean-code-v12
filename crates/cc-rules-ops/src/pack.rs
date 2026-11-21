//! [`BuiltinOpsPack`] — registers the seven Family-12 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::infinite_recursion::InfiniteRecursionRule;
use crate::missing_timeout::MissingTimeoutRule;
use crate::no_circuit_breaker::NoCircuitBreakerRule;
use crate::no_rate_limit::NoRateLimitRule;
use crate::retry_no_backoff::RetryNoBackoffRule;
use crate::unbounded_memory::UnboundedMemoryRule;
use crate::unbounded_queue::UnboundedQueueRule;

/// Built-in Family-12 [`RulePack`] — seven probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinOpsPack;

impl BuiltinOpsPack {
    /// Stable pack id. Distinct from every other built-in pack id so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-ops";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static MISSING_TIMEOUT: MissingTimeoutRule = MissingTimeoutRule;
static RETRY_NO_BACKOFF: RetryNoBackoffRule = RetryNoBackoffRule;
static NO_CIRCUIT_BREAKER: NoCircuitBreakerRule = NoCircuitBreakerRule;
static UNBOUNDED_QUEUE: UnboundedQueueRule = UnboundedQueueRule;
static UNBOUNDED_MEMORY: UnboundedMemoryRule = UnboundedMemoryRule;
static NO_RATE_LIMIT: NoRateLimitRule = NoRateLimitRule;
static INFINITE_RECURSION: InfiniteRecursionRule = InfiniteRecursionRule;

static RULES: &[&'static dyn Rule] = &[
    &MISSING_TIMEOUT,
    &RETRY_NO_BACKOFF,
    &NO_CIRCUIT_BREAKER,
    &UNBOUNDED_QUEUE,
    &UNBOUNDED_MEMORY,
    &NO_RATE_LIMIT,
    &INFINITE_RECURSION,
];

impl RulePack for BuiltinOpsPack {
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
