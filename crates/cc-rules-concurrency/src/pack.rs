//! [`BuiltinConcurrencyPack`] — registers the eight Family-5 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::context_no_propagate::ContextNoPropagateRule;
use crate::copy_loop_var::CopyLoopVarRule;
use crate::leaked_task::LeakedTaskRule;
use crate::lock_inversion::LockInversionRule;
use crate::race::RaceRule;
use crate::signal_unbuffered::SignalUnbufferedRule;
use crate::toctou::ToctouRule;
use crate::waitgroup_add_in_goroutine::WaitgroupAddInGoroutineRule;

/// Built-in Family-5 [`RulePack`] — eight probes registered at boot.
///
/// `R-ERR-ACTION`: registry rejection of this pack means the kernel API
/// drifted; bump `kernel_api_min` and re-vendor.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinConcurrencyPack;

impl BuiltinConcurrencyPack {
    /// Stable pack id. Distinct from `cc-builtin-tier0`, `cc-builtin-secrets`,
    /// `cc-builtin-perf`, and `cc-builtin-bugs` so the registry can host
    /// them all side-by-side without colliding.
    pub const PACK_ID: &'static str = "cc-builtin-concurrency";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static RACE: RaceRule = RaceRule;
static LOCK_INVERSION: LockInversionRule = LockInversionRule;
static LEAKED_TASK: LeakedTaskRule = LeakedTaskRule;
static TOCTOU: ToctouRule = ToctouRule;
static WAITGROUP_ADD_IN_GOROUTINE: WaitgroupAddInGoroutineRule = WaitgroupAddInGoroutineRule;
static SIGNAL_UNBUFFERED: SignalUnbufferedRule = SignalUnbufferedRule;

// Phase 9 (Go-deep-dive).
static CONTEXT_NO_PROPAGATE: ContextNoPropagateRule = ContextNoPropagateRule;
static COPY_LOOP_VAR: CopyLoopVarRule = CopyLoopVarRule;

static RULES: &[&'static dyn Rule] = &[
    &RACE,
    &LOCK_INVERSION,
    &LEAKED_TASK,
    &TOCTOU,
    &WAITGROUP_ADD_IN_GOROUTINE,
    &SIGNAL_UNBUFFERED,
    // Phase 9 (Go).
    &CONTEXT_NO_PROPAGATE,
    &COPY_LOOP_VAR,
];

impl RulePack for BuiltinConcurrencyPack {
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
