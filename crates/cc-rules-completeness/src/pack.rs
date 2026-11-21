//! [`BuiltinCompletenessPack`] — registers all 30 Family-25 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::chain::consumer_no_emitter::ConsumerNoEmitterRule;
use crate::chain::event_no_consumer::EventNoConsumerRule;
use crate::chain::fn_in_pathway_no_registry::FnInPathwayNoRegistryRule;
use crate::chain::fn_no_event_emit::FnNoEventEmitRule;
use crate::chain::fn_no_typed_error::FnNoTypedErrorRule;
use crate::contract::errata_anchor_invalid::ErrataAnchorInvalidRule;
use crate::contract::event_unsigned::EventUnsignedRule;
use crate::contract::invariant_unmonitored::InvariantUnmonitoredRule;
use crate::contract::postcondition_missing::PostconditionMissingRule;
use crate::contract::precondition_missing::PreconditionMissingRule;
use crate::decoration::circuit_breaker_missing::CircuitBreakerMissingRule;
use crate::decoration::rate_limit_missing::RateLimitMissingRule;
use crate::decoration::retry_no_backoff::RetryNoBackoffRule;
use crate::decoration::timeout_missing::TimeoutMissingRule;
use crate::error::bare_reraise::BareReraiseRule;
use crate::error::errcode_collision::ErrcodeCollisionRule;
use crate::error::no_errcode::NoErrcodeRule;
use crate::error::no_typed_class::NoTypedClassRule;
use crate::error::swallowed_with_log::SwallowedWithLogRule;
use crate::meta::duplicate_registration::DuplicateRegistrationRule;
use crate::meta::envelope_missing::EnvelopeMissingRule;
use crate::meta::fn_missing_decoration::FnMissingDecorationRule;
use crate::meta::io_schema_missing::IoSchemaMissingRule;
use crate::meta::side_effect_undeclared::SideEffectUndeclaredRule;
use crate::observe::missing_correlation_id::MissingCorrelationIdRule;
use crate::observe::public_fn_untraced::PublicFnUntracedRule;
use crate::observe::silent_io::SilentIoRule;
use crate::observe::span_name_drift::SpanNameDriftRule;
use crate::safety::public_fn_no_test::PublicFnNoTestRule;
use crate::safety::unsafe_block_no_safety_comment::UnsafeBlockNoSafetyCommentRule;

/// Built-in Family-25 [`RulePack`] — 30 structural-completeness probes.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinCompletenessPack;

impl BuiltinCompletenessPack {
    /// Stable pack id.
    pub const PACK_ID: &'static str = "cc-builtin-completeness";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

// observe (4)
static PUBLIC_FN_UNTRACED: PublicFnUntracedRule = PublicFnUntracedRule;
static SPAN_NAME_DRIFT: SpanNameDriftRule = SpanNameDriftRule;
static MISSING_CORRELATION_ID: MissingCorrelationIdRule = MissingCorrelationIdRule;
static SILENT_IO: SilentIoRule = SilentIoRule;
// meta (5)
static FN_MISSING_DECORATION: FnMissingDecorationRule = FnMissingDecorationRule;
static SIDE_EFFECT_UNDECLARED: SideEffectUndeclaredRule = SideEffectUndeclaredRule;
static ENVELOPE_MISSING: EnvelopeMissingRule = EnvelopeMissingRule;
static IO_SCHEMA_MISSING: IoSchemaMissingRule = IoSchemaMissingRule;
static DUPLICATE_REGISTRATION: DuplicateRegistrationRule = DuplicateRegistrationRule;
// contract (5)
static PRECONDITION_MISSING: PreconditionMissingRule = PreconditionMissingRule;
static POSTCONDITION_MISSING: PostconditionMissingRule = PostconditionMissingRule;
static INVARIANT_UNMONITORED: InvariantUnmonitoredRule = InvariantUnmonitoredRule;
static EVENT_UNSIGNED: EventUnsignedRule = EventUnsignedRule;
static ERRATA_ANCHOR_INVALID: ErrataAnchorInvalidRule = ErrataAnchorInvalidRule;
// error (5)
static NO_TYPED_CLASS: NoTypedClassRule = NoTypedClassRule;
static NO_ERRCODE: NoErrcodeRule = NoErrcodeRule;
static ERRCODE_COLLISION: ErrcodeCollisionRule = ErrcodeCollisionRule;
static BARE_RERAISE: BareReraiseRule = BareReraiseRule;
static SWALLOWED_WITH_LOG: SwallowedWithLogRule = SwallowedWithLogRule;
// decoration (4)
static TIMEOUT_MISSING: TimeoutMissingRule = TimeoutMissingRule;
static RETRY_NO_BACKOFF: RetryNoBackoffRule = RetryNoBackoffRule;
static CIRCUIT_BREAKER_MISSING: CircuitBreakerMissingRule = CircuitBreakerMissingRule;
static RATE_LIMIT_MISSING: RateLimitMissingRule = RateLimitMissingRule;
// chain (5)
static FN_IN_PATHWAY_NO_REGISTRY: FnInPathwayNoRegistryRule = FnInPathwayNoRegistryRule;
static FN_NO_TYPED_ERROR: FnNoTypedErrorRule = FnNoTypedErrorRule;
static FN_NO_EVENT_EMIT: FnNoEventEmitRule = FnNoEventEmitRule;
static EVENT_NO_CONSUMER: EventNoConsumerRule = EventNoConsumerRule;
static CONSUMER_NO_EMITTER: ConsumerNoEmitterRule = ConsumerNoEmitterRule;
// safety (Phase 10) (2)
static PUBLIC_FN_NO_TEST: PublicFnNoTestRule = PublicFnNoTestRule;
static UNSAFE_BLOCK_NO_SAFETY_COMMENT: UnsafeBlockNoSafetyCommentRule =
    UnsafeBlockNoSafetyCommentRule;

static RULES: &[&'static dyn Rule] = &[
    &PUBLIC_FN_UNTRACED,
    &SPAN_NAME_DRIFT,
    &MISSING_CORRELATION_ID,
    &SILENT_IO,
    &FN_MISSING_DECORATION,
    &SIDE_EFFECT_UNDECLARED,
    &ENVELOPE_MISSING,
    &IO_SCHEMA_MISSING,
    &DUPLICATE_REGISTRATION,
    &PRECONDITION_MISSING,
    &POSTCONDITION_MISSING,
    &INVARIANT_UNMONITORED,
    &EVENT_UNSIGNED,
    &ERRATA_ANCHOR_INVALID,
    &NO_TYPED_CLASS,
    &NO_ERRCODE,
    &ERRCODE_COLLISION,
    &BARE_RERAISE,
    &SWALLOWED_WITH_LOG,
    &TIMEOUT_MISSING,
    &RETRY_NO_BACKOFF,
    &CIRCUIT_BREAKER_MISSING,
    &RATE_LIMIT_MISSING,
    &FN_IN_PATHWAY_NO_REGISTRY,
    &FN_NO_TYPED_ERROR,
    &FN_NO_EVENT_EMIT,
    &EVENT_NO_CONSUMER,
    &CONSUMER_NO_EMITTER,
    &PUBLIC_FN_NO_TEST,
    &UNSAFE_BLOCK_NO_SAFETY_COMMENT,
];

impl RulePack for BuiltinCompletenessPack {
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
