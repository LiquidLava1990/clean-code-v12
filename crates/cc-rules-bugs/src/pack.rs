//! [`BuiltinBugsPack`] — registers the fifty-four Family-3 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::absurd_extreme_comparison::AbsurdExtremeComparisonRule;
use crate::always_throws::AlwaysThrowsRule;
use crate::arithmetic_side_effects::ArithmeticSideEffectsRule;
use crate::as_conversions::AsConversionsRule;
use crate::assert_with_tuple::AssertWithTupleRule;
use crate::bad_bit_mask::BadBitMaskRule;
use crate::body_close_missing::BodyCloseMissingRule;
use crate::broad_pytest_raises::BroadPytestRaisesRule;
use crate::callout_under_lock::CalloutUnderLockRule;
use crate::cast_nan_to_int::CastNanToIntRule;
use crate::cast_possible_truncation::CastPossibleTruncationRule;
use crate::cast_precision_loss::CastPrecisionLossRule;
use crate::clone_on_ref_ptr::CloneOnRefPtrRule;
use crate::cmp_to_nan::CmpToNanRule;
use crate::dead_thread::DeadThreadRule;
use crate::default_numeric_fallback::DefaultNumericFallbackRule;
use crate::deferred_close_no_err::DeferredCloseNoErrRule;
use crate::duplicate_dict_keys::DuplicateDictKeysRule;
use crate::equals_hashcode_pair::EqualsHashcodePairRule;
use crate::err_named_inconsistently::ErrNamedInconsistentlyRule;
use crate::errcheck_json::ErrcheckJsonRule;
use crate::float_money::FloatMoneyRule;
use crate::fn_call_in_default_arg::FnCallInDefaultArgRule;
use crate::format_string_drift::FormatStringDriftRule;
use crate::furb_dict_get_with_none_default::FurbDictGetWithNoneDefaultRule;
use crate::furb_for_else_loop_unused::FurbForElseLoopUnusedRule;
use crate::furb_implicit_int_str_concat::FurbImplicitIntStrConcatRule;
use crate::govet_assign_to_self::GovetAssignToSelfRule;
use crate::govet_copylocks::GovetCopylocksRule;
use crate::govet_lostcancel::GovetLostcancelRule;
use crate::govet_nilness_check::GovetNilnessCheckRule;
use crate::govet_printf_format::GovetPrintfFormatRule;
use crate::govet_struct_tag_well_formed::GovetStructTagWellFormedRule;
use crate::govet_unkeyed_composite::GovetUnkeyedCompositeRule;
use crate::govet_unreachable_code::GovetUnreachableCodeRule;
use crate::html_url_javascript::HtmlUrlJavascriptRule;
use crate::identity_binary_expr::IdentityBinaryExprRule;
use crate::locale_dependent::LocaleDependentRule;
use crate::mutable_arg_default::MutableArgDefaultRule;
use crate::mutate_during_iteration::MutateDuringIterationRule;
use crate::nilerr::NilerrRule;
use crate::null_propagation::NullPropagationRule;
use crate::off_by_one::OffByOneRule;
use crate::one_ticket_per_refusal::OneTicketPerRefusalRule;
use crate::python_assert_in_production::PythonAssertInProductionRule;
use crate::regex_invalid::RegexInvalidRule;
use crate::shift_amount_oor::ShiftAmountOorRule;
use crate::state_machine::StateMachineRule;
use crate::tick_leak::TickLeakRule;
use crate::time_bomb::TimeBombRule;
use crate::type_confusion::TypeConfusionRule;
use crate::unbounded_detail_text::UnboundedDetailTextRule;
use crate::unused_loop_variable::UnusedLoopVariableRule;
use crate::use_after_move::UseAfterMoveRule;

/// Built-in Family-3 [`RulePack`] — fifty-four probes registered at
/// boot (Phase 3 + Phase 7 + Phase 8 + Phase 9 Python/Go/Rust + Phase
/// 10 Python long-tail + Phase 10 Batch L cross-cutting + Phase 10
/// Rust long-tail + Phase 11 Go govet long-tail + Phase 12 final
/// OSS sweep).
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinBugsPack;

impl BuiltinBugsPack {
    /// Stable pack id. Distinct from `cc-builtin-tier0` / `cc-builtin-secrets`
    /// / `cc-builtin-perf` so the registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-bugs";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static NULL_PROPAGATION: NullPropagationRule = NullPropagationRule;
static OFF_BY_ONE: OffByOneRule = OffByOneRule;
static TYPE_CONFUSION: TypeConfusionRule = TypeConfusionRule;
static STATE_MACHINE: StateMachineRule = StateMachineRule;
static TIME_BOMB: TimeBombRule = TimeBombRule;
static FLOAT_MONEY: FloatMoneyRule = FloatMoneyRule;
static LOCALE_DEPENDENT: LocaleDependentRule = LocaleDependentRule;

static EQUALS_HASHCODE_PAIR: EqualsHashcodePairRule = EqualsHashcodePairRule;
static IDENTITY_BINARY_EXPR: IdentityBinaryExprRule = IdentityBinaryExprRule;
static CMP_TO_NAN: CmpToNanRule = CmpToNanRule;
static SHIFT_AMOUNT_OOR: ShiftAmountOorRule = ShiftAmountOorRule;
static FORMAT_STRING_DRIFT: FormatStringDriftRule = FormatStringDriftRule;
static REGEX_INVALID: RegexInvalidRule = RegexInvalidRule;
static DEFERRED_CLOSE_NO_ERR: DeferredCloseNoErrRule = DeferredCloseNoErrRule;
static MUTATE_DURING_ITERATION: MutateDuringIterationRule = MutateDuringIterationRule;

static TICK_LEAK: TickLeakRule = TickLeakRule;
static DEAD_THREAD: DeadThreadRule = DeadThreadRule;
static ALWAYS_THROWS: AlwaysThrowsRule = AlwaysThrowsRule;
static USE_AFTER_MOVE: UseAfterMoveRule = UseAfterMoveRule;
static HTML_URL_JAVASCRIPT: HtmlUrlJavascriptRule = HtmlUrlJavascriptRule;

// Phase 9 probes (Python-deep-dive, ruff B0xx).
static MUTABLE_ARG_DEFAULT: MutableArgDefaultRule = MutableArgDefaultRule;
static UNUSED_LOOP_VARIABLE: UnusedLoopVariableRule = UnusedLoopVariableRule;
static FN_CALL_IN_DEFAULT_ARG: FnCallInDefaultArgRule = FnCallInDefaultArgRule;
static ASSERT_WITH_TUPLE: AssertWithTupleRule = AssertWithTupleRule;
static BROAD_PYTEST_RAISES: BroadPytestRaisesRule = BroadPytestRaisesRule;

// Phase 9 probes (Go-deep-dive, staticcheck + golangci).
static BODY_CLOSE_MISSING: BodyCloseMissingRule = BodyCloseMissingRule;
static ERRCHECK_JSON: ErrcheckJsonRule = ErrcheckJsonRule;
static ERR_NAMED_INCONSISTENTLY: ErrNamedInconsistentlyRule = ErrNamedInconsistentlyRule;
static NILERR: NilerrRule = NilerrRule;

// Phase 9 probes (Rust-deep-dive, clippy).
static ABSURD_EXTREME_COMPARISON: AbsurdExtremeComparisonRule = AbsurdExtremeComparisonRule;
static BAD_BIT_MASK: BadBitMaskRule = BadBitMaskRule;
static CAST_NAN_TO_INT: CastNanToIntRule = CastNanToIntRule;
static CAST_POSSIBLE_TRUNCATION: CastPossibleTruncationRule = CastPossibleTruncationRule;
static CAST_PRECISION_LOSS: CastPrecisionLossRule = CastPrecisionLossRule;

// Phase 10 probes (Python long-tail, ruff FURB / ISC).
static FURB_IMPLICIT_INT_STR_CONCAT: FurbImplicitIntStrConcatRule = FurbImplicitIntStrConcatRule;
static FURB_DICT_GET_WITH_NONE_DEFAULT: FurbDictGetWithNoneDefaultRule =
    FurbDictGetWithNoneDefaultRule;
static FURB_FOR_ELSE_LOOP_UNUSED: FurbForElseLoopUnusedRule = FurbForElseLoopUnusedRule;

// Phase 10 probes (Batch L — multi-language cross-cutting).
static DUPLICATE_DICT_KEYS: DuplicateDictKeysRule = DuplicateDictKeysRule;

// Phase 10 probes (Rust long-tail — clippy).
static ARITHMETIC_SIDE_EFFECTS: ArithmeticSideEffectsRule = ArithmeticSideEffectsRule;
static AS_CONVERSIONS: AsConversionsRule = AsConversionsRule;
static CLONE_ON_REF_PTR: CloneOnRefPtrRule = CloneOnRefPtrRule;
static DEFAULT_NUMERIC_FALLBACK: DefaultNumericFallbackRule = DefaultNumericFallbackRule;

// Phase 11 probes (Go govet long-tail — `unreachable` / `lostcancel` /
// `assign` / `copylocks` / `composites`).
static GOVET_UNREACHABLE_CODE: GovetUnreachableCodeRule = GovetUnreachableCodeRule;
static GOVET_LOSTCANCEL: GovetLostcancelRule = GovetLostcancelRule;
static GOVET_ASSIGN_TO_SELF: GovetAssignToSelfRule = GovetAssignToSelfRule;
static GOVET_COPYLOCKS: GovetCopylocksRule = GovetCopylocksRule;
static GOVET_UNKEYED_COMPOSITE: GovetUnkeyedCompositeRule = GovetUnkeyedCompositeRule;

// Phase 12 probes (final OSS long-tail sweep — Go nilness/printf/structtag
// + Python production-assert).
static GOVET_NILNESS_CHECK: GovetNilnessCheckRule = GovetNilnessCheckRule;
static GOVET_PRINTF_FORMAT: GovetPrintfFormatRule = GovetPrintfFormatRule;
static GOVET_STRUCT_TAG_WELL_FORMED: GovetStructTagWellFormedRule = GovetStructTagWellFormedRule;
static PYTHON_ASSERT_IN_PRODUCTION: PythonAssertInProductionRule = PythonAssertInProductionRule;
static CALLOUT_UNDER_LOCK: CalloutUnderLockRule = CalloutUnderLockRule;
static ONE_TICKET_PER_REFUSAL: OneTicketPerRefusalRule = OneTicketPerRefusalRule;
static UNBOUNDED_DETAIL_TEXT: UnboundedDetailTextRule = UnboundedDetailTextRule;

static RULES: &[&'static dyn Rule] = &[
    &NULL_PROPAGATION,
    &OFF_BY_ONE,
    &TYPE_CONFUSION,
    &STATE_MACHINE,
    &TIME_BOMB,
    &FLOAT_MONEY,
    &LOCALE_DEPENDENT,
    &EQUALS_HASHCODE_PAIR,
    &IDENTITY_BINARY_EXPR,
    &CMP_TO_NAN,
    &SHIFT_AMOUNT_OOR,
    &FORMAT_STRING_DRIFT,
    &REGEX_INVALID,
    &DEFERRED_CLOSE_NO_ERR,
    &MUTATE_DURING_ITERATION,
    &TICK_LEAK,
    &DEAD_THREAD,
    &ALWAYS_THROWS,
    &USE_AFTER_MOVE,
    &HTML_URL_JAVASCRIPT,
    // Phase 9 (Python).
    &MUTABLE_ARG_DEFAULT,
    &UNUSED_LOOP_VARIABLE,
    &FN_CALL_IN_DEFAULT_ARG,
    &ASSERT_WITH_TUPLE,
    &BROAD_PYTEST_RAISES,
    // Phase 9 (Go).
    &BODY_CLOSE_MISSING,
    &ERRCHECK_JSON,
    &ERR_NAMED_INCONSISTENTLY,
    &NILERR,
    // Phase 9 (Rust).
    &ABSURD_EXTREME_COMPARISON,
    &BAD_BIT_MASK,
    &CAST_NAN_TO_INT,
    &CAST_POSSIBLE_TRUNCATION,
    &CAST_PRECISION_LOSS,
    // Phase 10 (Python long-tail — FURB / ISC).
    &FURB_IMPLICIT_INT_STR_CONCAT,
    &FURB_DICT_GET_WITH_NONE_DEFAULT,
    &FURB_FOR_ELSE_LOOP_UNUSED,
    // Phase 10 (Batch L — multi-language cross-cutting).
    &DUPLICATE_DICT_KEYS,
    // Phase 10 (Rust long-tail — clippy).
    &ARITHMETIC_SIDE_EFFECTS,
    &AS_CONVERSIONS,
    &CLONE_ON_REF_PTR,
    &DEFAULT_NUMERIC_FALLBACK,
    // Phase 11 (Go govet long-tail).
    &GOVET_UNREACHABLE_CODE,
    &GOVET_LOSTCANCEL,
    &GOVET_ASSIGN_TO_SELF,
    &GOVET_COPYLOCKS,
    &GOVET_UNKEYED_COMPOSITE,
    // Phase 12 (final OSS long-tail sweep).
    &GOVET_NILNESS_CHECK,
    &GOVET_PRINTF_FORMAT,
    &GOVET_STRUCT_TAG_WELL_FORMED,
    &PYTHON_ASSERT_IN_PRODUCTION,
    // Batch 2 (Python reliability probes).
    &CALLOUT_UNDER_LOCK,
    &ONE_TICKET_PER_REFUSAL,
    &UNBOUNDED_DETAIL_TEXT,
];

impl RulePack for BuiltinBugsPack {
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
