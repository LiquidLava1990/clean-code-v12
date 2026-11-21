//! [`BuiltinTypesPack`] — registers every Family-22 probe.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::async_returns_null::AsyncReturnsNullRule;
use crate::await_thenable::AwaitThenableRule;
use crate::ban_ts_comment::BanTsCommentRule;
use crate::consistent_type_imports::ConsistentTypeImportsRule;
use crate::exhaustruct::ExhaustructRule;
use crate::implicit_any::ImplicitAnyRule;
use crate::lock_held_across_await::LockHeldAcrossAwaitRule;
use crate::no_base_to_string::NoBaseToStringRule;
use crate::no_confusing_void_expression::NoConfusingVoidExpressionRule;
use crate::no_explicit_any::NoExplicitAnyRule;
use crate::no_floating_promise::NoFloatingPromiseRule;
use crate::no_misused_promise::NoMisusedPromiseRule;
use crate::no_non_null_assertion::NoNonNullAssertionRule;
use crate::no_unnecessary_condition::NoUnnecessaryConditionRule;
use crate::no_unsafe_argument::NoUnsafeArgumentRule;
use crate::no_unsafe_enum_comparison::NoUnsafeEnumComparisonRule;
use crate::no_unsafe_return::NoUnsafeReturnRule;
use crate::no_unused_expressions::NoUnusedExpressionsRule;
use crate::no_var_requires::NoVarRequiresRule;
use crate::protocol_drift::ProtocolDriftRule;
use crate::strict_boolean_expressions::StrictBooleanExpressionsRule;
use crate::switch_exhaustiveness::SwitchExhaustivenessRule;
use crate::unjustified_ignore::UnjustifiedIgnoreRule;

/// Built-in Family-22 [`RulePack`] — every probe registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTypesPack;

impl BuiltinTypesPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-types";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static IMPLICIT_ANY: ImplicitAnyRule = ImplicitAnyRule;
static UNJUSTIFIED_IGNORE: UnjustifiedIgnoreRule = UnjustifiedIgnoreRule;
static PROTOCOL_DRIFT: ProtocolDriftRule = ProtocolDriftRule;
static NO_FLOATING_PROMISE: NoFloatingPromiseRule = NoFloatingPromiseRule;
static NO_MISUSED_PROMISE: NoMisusedPromiseRule = NoMisusedPromiseRule;
static NO_UNSAFE_ARGUMENT: NoUnsafeArgumentRule = NoUnsafeArgumentRule;
static NO_UNSAFE_RETURN: NoUnsafeReturnRule = NoUnsafeReturnRule;
static SWITCH_EXHAUSTIVENESS: SwitchExhaustivenessRule = SwitchExhaustivenessRule;
static LOCK_HELD_ACROSS_AWAIT: LockHeldAcrossAwaitRule = LockHeldAcrossAwaitRule;
static ASYNC_RETURNS_NULL: AsyncReturnsNullRule = AsyncReturnsNullRule;
static AWAIT_THENABLE: AwaitThenableRule = AwaitThenableRule;
static NO_UNNECESSARY_CONDITION: NoUnnecessaryConditionRule = NoUnnecessaryConditionRule;
static EXHAUSTRUCT: ExhaustructRule = ExhaustructRule;
static NO_EXPLICIT_ANY: NoExplicitAnyRule = NoExplicitAnyRule;
static NO_NON_NULL_ASSERTION: NoNonNullAssertionRule = NoNonNullAssertionRule;
static STRICT_BOOLEAN_EXPRESSIONS: StrictBooleanExpressionsRule = StrictBooleanExpressionsRule;
static NO_BASE_TO_STRING: NoBaseToStringRule = NoBaseToStringRule;
static NO_CONFUSING_VOID_EXPRESSION: NoConfusingVoidExpressionRule = NoConfusingVoidExpressionRule;
static NO_UNSAFE_ENUM_COMPARISON: NoUnsafeEnumComparisonRule = NoUnsafeEnumComparisonRule;
static BAN_TS_COMMENT: BanTsCommentRule = BanTsCommentRule;
static NO_UNUSED_EXPRESSIONS: NoUnusedExpressionsRule = NoUnusedExpressionsRule;
static NO_VAR_REQUIRES: NoVarRequiresRule = NoVarRequiresRule;
static CONSISTENT_TYPE_IMPORTS: ConsistentTypeImportsRule = ConsistentTypeImportsRule;

static RULES: &[&'static dyn Rule] = &[
    &IMPLICIT_ANY,
    &UNJUSTIFIED_IGNORE,
    &PROTOCOL_DRIFT,
    &NO_FLOATING_PROMISE,
    &NO_MISUSED_PROMISE,
    &NO_UNSAFE_ARGUMENT,
    &NO_UNSAFE_RETURN,
    &SWITCH_EXHAUSTIVENESS,
    &LOCK_HELD_ACROSS_AWAIT,
    &ASYNC_RETURNS_NULL,
    &AWAIT_THENABLE,
    &NO_UNNECESSARY_CONDITION,
    &EXHAUSTRUCT,
    &NO_EXPLICIT_ANY,
    &NO_NON_NULL_ASSERTION,
    &STRICT_BOOLEAN_EXPRESSIONS,
    &NO_BASE_TO_STRING,
    &NO_CONFUSING_VOID_EXPRESSION,
    &NO_UNSAFE_ENUM_COMPARISON,
    &BAN_TS_COMMENT,
    &NO_UNUSED_EXPRESSIONS,
    &NO_VAR_REQUIRES,
    &CONSISTENT_TYPE_IMPORTS,
];

impl RulePack for BuiltinTypesPack {
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
