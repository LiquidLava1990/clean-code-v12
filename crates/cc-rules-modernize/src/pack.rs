//! [`BuiltinModernizePack`] — registers the thirty-five Family-26
//! probes (10 from Phase 6 + 10 from Phase 8 + 5 from Phase 9 + 4
//! from Phase 10 Python + 3 from Phase 10 Rust + 3 from Phase 12).

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::banned_import_alias::BannedImportAliasRule;
use crate::bare_reraise_lossy::BareReraiseLossyRule;
use crate::callbacks_over_promises::CallbacksOverPromisesRule;
use crate::collapsible_if::CollapsibleIfRule;
use crate::commonjs_require::CommonjsRequireRule;
use crate::consistent_function_scoping::ConsistentFunctionScopingRule;
use crate::deprecated_typing_alias::DeprecatedTypingAliasRule;
use crate::deprecated_unittest_aliases::DeprecatedUnittestAliasesRule;
use crate::deprecated_unwrap::DeprecatedUnwrapRule;
use crate::dict_literal_over_call::DictLiteralOverCallRule;
use crate::django_locals_in_render::DjangoLocalsInRenderRule;
use crate::django_url_path_param_required::DjangoUrlPathParamRequiredRule;
use crate::legacy_format_macro::LegacyFormatMacroRule;
use crate::list_call_in_set_call::ListCallInSetCallRule;
use crate::logging_fstring::LoggingFstringRule;
use crate::manual_let_else::ManualLetElseRule;
use crate::no_array_for_each::NoArrayForEachRule;
use crate::numpy_legacy_random::NumpyLegacyRandomRule;
use crate::os_path_join::OsPathJoinRule;
use crate::pandas_chained_assignment::PandasChainedAssignmentRule;
use crate::python_dataclass_for_class_with_init::PythonDataclassForClassWithInitRule;
use crate::python_match_case_for_chain::PythonMatchCaseForChainRule;
use crate::python_walrus_for_assign_in_cond::PythonWalrusForAssignInCondRule;
use crate::redundant_closure::RedundantClosureRule;
use crate::simplify_boolean_expr::SimplifyBooleanExprRule;
use crate::string_format_legacy::StringFormatLegacyRule;
use crate::string_format_to_fstring::StringFormatToFstringRule;
use crate::sync_in_async_runtime::SyncInAsyncRuntimeRule;
use crate::template_over_concat::TemplateOverConcatRule;
use crate::thread_spawn_no_join::ThreadSpawnNoJoinRule;
use crate::try_consider_else::TryConsiderElseRule;
use crate::try_except_pass::TryExceptPassRule;
use crate::unnecessary_lazy_evaluations::UnnecessaryLazyEvaluationsRule;
use crate::use_pathlib_over_os::UsePathlibOverOsRule;
use crate::var_for_let::VarForLetRule;

/// Built-in Family-26 [`RulePack`] — thirty-five modernization probes.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinModernizePack;

impl BuiltinModernizePack {
    /// Stable pack id, distinct from every sibling pack so the registry
    /// can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-modernize";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

// Phase 6 probes (original ten).
static STRING_FORMAT_LEGACY: StringFormatLegacyRule = StringFormatLegacyRule;
static DEPRECATED_TYPING_ALIAS: DeprecatedTypingAliasRule = DeprecatedTypingAliasRule;
static OS_PATH_JOIN: OsPathJoinRule = OsPathJoinRule;
static VAR_FOR_LET: VarForLetRule = VarForLetRule;
static COMMONJS_REQUIRE: CommonjsRequireRule = CommonjsRequireRule;
static CALLBACKS_OVER_PROMISES: CallbacksOverPromisesRule = CallbacksOverPromisesRule;
static DEPRECATED_UNWRAP: DeprecatedUnwrapRule = DeprecatedUnwrapRule;
static LEGACY_FORMAT_MACRO: LegacyFormatMacroRule = LegacyFormatMacroRule;
static THREAD_SPAWN_NO_JOIN: ThreadSpawnNoJoinRule = ThreadSpawnNoJoinRule;
static SYNC_IN_ASYNC_RUNTIME: SyncInAsyncRuntimeRule = SyncInAsyncRuntimeRule;

// Phase 8 probes (new ten).
static SIMPLIFY_BOOLEAN_EXPR: SimplifyBooleanExprRule = SimplifyBooleanExprRule;
static TEMPLATE_OVER_CONCAT: TemplateOverConcatRule = TemplateOverConcatRule;
static NO_ARRAY_FOR_EACH: NoArrayForEachRule = NoArrayForEachRule;
static USE_PATHLIB_OVER_OS: UsePathlibOverOsRule = UsePathlibOverOsRule;
static BARE_RERAISE_LOSSY: BareReraiseLossyRule = BareReraiseLossyRule;
static DICT_LITERAL_OVER_CALL: DictLiteralOverCallRule = DictLiteralOverCallRule;
static LIST_CALL_IN_SET_CALL: ListCallInSetCallRule = ListCallInSetCallRule;
static STRING_FORMAT_TO_FSTRING: StringFormatToFstringRule = StringFormatToFstringRule;
static DEPRECATED_UNITTEST_ALIASES: DeprecatedUnittestAliasesRule = DeprecatedUnittestAliasesRule;
static CONSISTENT_FUNCTION_SCOPING: ConsistentFunctionScopingRule = ConsistentFunctionScopingRule;

// Phase 9 probes (Python-deep-dive, ruff G/SIM/TRY/ICN/S).
static LOGGING_FSTRING: LoggingFstringRule = LoggingFstringRule;
static TRY_CONSIDER_ELSE: TryConsiderElseRule = TryConsiderElseRule;
static COLLAPSIBLE_IF: CollapsibleIfRule = CollapsibleIfRule;
static BANNED_IMPORT_ALIAS: BannedImportAliasRule = BannedImportAliasRule;
static TRY_EXCEPT_PASS: TryExceptPassRule = TryExceptPassRule;

// Phase 10 probes (Python long-tail — DJ-Django, NPY-NumPy, PD-pandas).
static DJANGO_URL_PATH_PARAM_REQUIRED: DjangoUrlPathParamRequiredRule =
    DjangoUrlPathParamRequiredRule;
static DJANGO_LOCALS_IN_RENDER: DjangoLocalsInRenderRule = DjangoLocalsInRenderRule;
static NUMPY_LEGACY_RANDOM: NumpyLegacyRandomRule = NumpyLegacyRandomRule;
static PANDAS_CHAINED_ASSIGNMENT: PandasChainedAssignmentRule = PandasChainedAssignmentRule;

// Phase 10 probes (Rust long-tail — clippy).
static MANUAL_LET_ELSE: ManualLetElseRule = ManualLetElseRule;
static REDUNDANT_CLOSURE: RedundantClosureRule = RedundantClosureRule;
static UNNECESSARY_LAZY_EVALUATIONS: UnnecessaryLazyEvaluationsRule =
    UnnecessaryLazyEvaluationsRule;

// Phase 12 probes (final OSS long-tail sweep — Python modernization trio).
static PYTHON_WALRUS_FOR_ASSIGN_IN_COND: PythonWalrusForAssignInCondRule =
    PythonWalrusForAssignInCondRule;
static PYTHON_MATCH_CASE_FOR_CHAIN: PythonMatchCaseForChainRule = PythonMatchCaseForChainRule;
static PYTHON_DATACLASS_FOR_CLASS_WITH_INIT: PythonDataclassForClassWithInitRule =
    PythonDataclassForClassWithInitRule;

static RULES: &[&'static dyn Rule] = &[
    // Phase 6.
    &STRING_FORMAT_LEGACY,
    &DEPRECATED_TYPING_ALIAS,
    &OS_PATH_JOIN,
    &VAR_FOR_LET,
    &COMMONJS_REQUIRE,
    &CALLBACKS_OVER_PROMISES,
    &DEPRECATED_UNWRAP,
    &LEGACY_FORMAT_MACRO,
    &THREAD_SPAWN_NO_JOIN,
    &SYNC_IN_ASYNC_RUNTIME,
    // Phase 8.
    &SIMPLIFY_BOOLEAN_EXPR,
    &TEMPLATE_OVER_CONCAT,
    &NO_ARRAY_FOR_EACH,
    &USE_PATHLIB_OVER_OS,
    &BARE_RERAISE_LOSSY,
    &DICT_LITERAL_OVER_CALL,
    &LIST_CALL_IN_SET_CALL,
    &STRING_FORMAT_TO_FSTRING,
    &DEPRECATED_UNITTEST_ALIASES,
    &CONSISTENT_FUNCTION_SCOPING,
    // Phase 9 (Python).
    &LOGGING_FSTRING,
    &TRY_CONSIDER_ELSE,
    &COLLAPSIBLE_IF,
    &BANNED_IMPORT_ALIAS,
    &TRY_EXCEPT_PASS,
    // Phase 10 (Python — Django/NumPy/pandas).
    &DJANGO_URL_PATH_PARAM_REQUIRED,
    &DJANGO_LOCALS_IN_RENDER,
    &NUMPY_LEGACY_RANDOM,
    &PANDAS_CHAINED_ASSIGNMENT,
    // Phase 10 (Rust long-tail — clippy).
    &MANUAL_LET_ELSE,
    &REDUNDANT_CLOSURE,
    &UNNECESSARY_LAZY_EVALUATIONS,
    // Phase 12 (final OSS long-tail sweep — Python modernization trio).
    &PYTHON_WALRUS_FOR_ASSIGN_IN_COND,
    &PYTHON_MATCH_CASE_FOR_CHAIN,
    &PYTHON_DATACLASS_FOR_CLASS_WITH_INIT,
];

impl RulePack for BuiltinModernizePack {
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
