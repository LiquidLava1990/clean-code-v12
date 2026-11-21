//! [`BuiltinTier0Pack`] — registers all Tier-0 rules.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::error::bare::BareCatchRule;
use crate::error::broad_catch::BroadCatchRule;
use crate::error::no_action::NoActionRule;
use crate::meta::new_file_clean::NewFileCleanRule;
use crate::meta::refactor_drift::RefactorDriftRule;
use crate::shape::boolean_complexity::BooleanComplexityRule;
use crate::shape::cognitive::CognitiveRule;
use crate::shape::cyclomatic::CyclomaticRule;
use crate::shape::dead_code::DeadCodeRule;
use crate::shape::duplication::DuplicationRule;
use crate::shape::expression_depth::ExpressionDepthRule;
use crate::shape::file_length::FileLengthRule;
use crate::shape::fn_length::FnLengthRule;
use crate::shape::god_struct::GodStructRule;
use crate::shape::identifier_entropy::IdentifierEntropyRule;
use crate::shape::lambda_complexity::LambdaComplexityRule;
use crate::shape::local_var_count::LocalVarCountRule;
use crate::shape::naming_drift::NamingDriftRule;
use crate::shape::nesting_depth::NestingDepthRule;
use crate::shape::nesting_early_return::NestingEarlyReturnRule;
use crate::shape::no_inheritance::NoInheritanceRule;
use crate::shape::param_count::ParamCountRule;
use crate::shape::public_surface_size::PublicSurfaceSizeRule;
use crate::shape::return_count::ReturnCountRule;
use crate::shape::statement_count::StatementCountRule;
use crate::shape::swallowed_with_log::SwallowedWithLogRule;
use crate::type_coverage::coverage::TypeCoverageRule;

/// Built-in Tier-0 [`RulePack`] — every forever rule registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTier0Pack;

impl BuiltinTier0Pack {
    /// Stable pack id. Distinct from `cc-rules::BuiltinPack` so the kernel
    /// can register both (the placeholder pack ships zero rules).
    pub const PACK_ID: &'static str = "cc-builtin-tier0";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static FN_LENGTH: FnLengthRule = FnLengthRule;
static FILE_LENGTH: FileLengthRule = FileLengthRule;
static NESTING_DEPTH: NestingDepthRule = NestingDepthRule;
static PARAM_COUNT: ParamCountRule = ParamCountRule;
static CYCLOMATIC: CyclomaticRule = CyclomaticRule;
static COGNITIVE: CognitiveRule = CognitiveRule;
static NO_INHERITANCE: NoInheritanceRule = NoInheritanceRule;
static BARE_CATCH: BareCatchRule = BareCatchRule;
static BROAD_CATCH: BroadCatchRule = BroadCatchRule;
static DUPLICATION: DuplicationRule = DuplicationRule;
static DEAD_CODE: DeadCodeRule = DeadCodeRule;
static TYPE_COVERAGE: TypeCoverageRule = TypeCoverageRule;
static NAMING_DRIFT: NamingDriftRule = NamingDriftRule;
static NESTING_EARLY_RETURN: NestingEarlyReturnRule = NestingEarlyReturnRule;
static NO_ACTION: NoActionRule = NoActionRule;
static REFACTOR_DRIFT: RefactorDriftRule = RefactorDriftRule;
static NEW_FILE_CLEAN: NewFileCleanRule = NewFileCleanRule;
// Phase-7 Tier-0 forever-rule gap fills.
static RETURN_COUNT: ReturnCountRule = ReturnCountRule;
static BOOLEAN_COMPLEXITY: BooleanComplexityRule = BooleanComplexityRule;
static LOCAL_VAR_COUNT: LocalVarCountRule = LocalVarCountRule;
static STATEMENT_COUNT: StatementCountRule = StatementCountRule;
static IDENTIFIER_ENTROPY: IdentifierEntropyRule = IdentifierEntropyRule;
static LAMBDA_COMPLEXITY: LambdaComplexityRule = LambdaComplexityRule;
static PUBLIC_SURFACE_SIZE: PublicSurfaceSizeRule = PublicSurfaceSizeRule;
static GOD_STRUCT: GodStructRule = GodStructRule;
static EXPRESSION_DEPTH: ExpressionDepthRule = ExpressionDepthRule;
static SWALLOWED_WITH_LOG: SwallowedWithLogRule = SwallowedWithLogRule;

static RULES: &[&'static dyn Rule] = &[
    &FN_LENGTH,
    &FILE_LENGTH,
    &NESTING_DEPTH,
    &PARAM_COUNT,
    &CYCLOMATIC,
    &COGNITIVE,
    &NO_INHERITANCE,
    &BARE_CATCH,
    &BROAD_CATCH,
    &DUPLICATION,
    &DEAD_CODE,
    &TYPE_COVERAGE,
    &NAMING_DRIFT,
    &NESTING_EARLY_RETURN,
    &NO_ACTION,
    &REFACTOR_DRIFT,
    &NEW_FILE_CLEAN,
    &RETURN_COUNT,
    &BOOLEAN_COMPLEXITY,
    &LOCAL_VAR_COUNT,
    &STATEMENT_COUNT,
    &IDENTIFIER_ENTROPY,
    &LAMBDA_COMPLEXITY,
    &PUBLIC_SURFACE_SIZE,
    &GOD_STRUCT,
    &EXPRESSION_DEPTH,
    &SWALLOWED_WITH_LOG,
];

impl RulePack for BuiltinTier0Pack {
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
