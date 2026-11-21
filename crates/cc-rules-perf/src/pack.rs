//! [`BuiltinPerfPack`] — registers all twenty-four Family-2 performance rules.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::alloc_in_loop::AllocInLoopRule;
use crate::box_collection::BoxCollectionRule;
use crate::boxed_local::BoxedLocalRule;
use crate::branches_sharing_code::BranchesSharingCodeRule;
use crate::cloned_instead_of_copied::ClonedInsteadOfCopiedRule;
use crate::cmp_owned::CmpOwnedRule;
use crate::collection_is_never_read::CollectionIsNeverReadRule;
use crate::dict_iteration_with_keys::DictIterationWithKeysRule;
use crate::format_in_format_args::FormatInFormatArgsRule;
use crate::gc_pressure::GcPressureRule;
use crate::gil_trap::GilTrapRule;
use crate::makezero_with_append::MakezeroWithAppendRule;
use crate::missing_memoization::MissingMemoizationRule;
use crate::n_plus_one_orm::NPlusOneOrmRule;
use crate::no_context_in_http::NoContextInHttpRule;
use crate::prealloc_slice_in_loop::PreallocSliceInLoopRule;
use crate::regex_compile_in_function::RegexCompileInFunctionRule;
use crate::regex_compile_in_loop::RegexCompileInLoopRule;
use crate::string_concat_in_recursion::StringConcatInRecursionRule;
use crate::string_concat_loop::StringConcatLoopRule;
use crate::sync_in_async::SyncInAsyncRule;
use crate::useless_collect::UselessCollectRule;
use crate::wasted_assign::WastedAssignRule;
use crate::wrong_collection::WrongCollectionRule;

/// Built-in Family-2 [`RulePack`] — twenty-four adoption-friendly perf
/// probes (Phase 1 + Phase 9 Go-deep-dive + Phase 9 Rust-deep-dive
/// + Phase 10 Rust long-tail + Phase 12 final OSS sweep).
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinPerfPack;

impl BuiltinPerfPack {
    /// Stable pack id. Distinct from the Tier-0 pack id so the kernel can
    /// register both without collision.
    pub const PACK_ID: &'static str = "cc-builtin-perf";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static N_PLUS_ONE: NPlusOneOrmRule = NPlusOneOrmRule;
static SYNC_IN_ASYNC: SyncInAsyncRule = SyncInAsyncRule;
static ALLOC_IN_LOOP: AllocInLoopRule = AllocInLoopRule;
static WRONG_COLLECTION: WrongCollectionRule = WrongCollectionRule;
static REGEX_COMPILE_IN_LOOP: RegexCompileInLoopRule = RegexCompileInLoopRule;
static MISSING_MEMOIZATION: MissingMemoizationRule = MissingMemoizationRule;
static GIL_TRAP: GilTrapRule = GilTrapRule;
static GC_PRESSURE: GcPressureRule = GcPressureRule;
static STRING_CONCAT_LOOP: StringConcatLoopRule = StringConcatLoopRule;

// Phase 9 (Go-deep-dive).
static MAKEZERO_WITH_APPEND: MakezeroWithAppendRule = MakezeroWithAppendRule;
static PREALLOC_SLICE_IN_LOOP: PreallocSliceInLoopRule = PreallocSliceInLoopRule;
static NO_CONTEXT_IN_HTTP: NoContextInHttpRule = NoContextInHttpRule;
static WASTED_ASSIGN: WastedAssignRule = WastedAssignRule;

// Phase 9 (Rust-deep-dive).
static CLONED_INSTEAD_OF_COPIED: ClonedInsteadOfCopiedRule = ClonedInsteadOfCopiedRule;
static CMP_OWNED: CmpOwnedRule = CmpOwnedRule;
static BOX_COLLECTION: BoxCollectionRule = BoxCollectionRule;
static BOXED_LOCAL: BoxedLocalRule = BoxedLocalRule;
static BRANCHES_SHARING_CODE: BranchesSharingCodeRule = BranchesSharingCodeRule;

// Phase 10 (Rust long-tail — clippy).
static COLLECTION_IS_NEVER_READ: CollectionIsNeverReadRule = CollectionIsNeverReadRule;
static USELESS_COLLECT: UselessCollectRule = UselessCollectRule;
static FORMAT_IN_FORMAT_ARGS: FormatInFormatArgsRule = FormatInFormatArgsRule;

// Phase 12 (final OSS long-tail sweep — Python perf trio).
static REGEX_COMPILE_IN_FUNCTION: RegexCompileInFunctionRule = RegexCompileInFunctionRule;
static STRING_CONCAT_IN_RECURSION: StringConcatInRecursionRule = StringConcatInRecursionRule;
static DICT_ITERATION_WITH_KEYS: DictIterationWithKeysRule = DictIterationWithKeysRule;

static RULES: &[&'static dyn Rule] = &[
    &N_PLUS_ONE,
    &SYNC_IN_ASYNC,
    &ALLOC_IN_LOOP,
    &WRONG_COLLECTION,
    &REGEX_COMPILE_IN_LOOP,
    &MISSING_MEMOIZATION,
    &GIL_TRAP,
    &GC_PRESSURE,
    &STRING_CONCAT_LOOP,
    // Phase 9 (Go).
    &MAKEZERO_WITH_APPEND,
    &PREALLOC_SLICE_IN_LOOP,
    &NO_CONTEXT_IN_HTTP,
    &WASTED_ASSIGN,
    // Phase 9 (Rust).
    &CLONED_INSTEAD_OF_COPIED,
    &CMP_OWNED,
    &BOX_COLLECTION,
    &BOXED_LOCAL,
    &BRANCHES_SHARING_CODE,
    // Phase 10 (Rust long-tail).
    &COLLECTION_IS_NEVER_READ,
    &USELESS_COLLECT,
    &FORMAT_IN_FORMAT_ARGS,
    // Phase 12 (final OSS long-tail sweep).
    &REGEX_COMPILE_IN_FUNCTION,
    &STRING_CONCAT_IN_RECURSION,
    &DICT_ITERATION_WITH_KEYS,
];

impl RulePack for BuiltinPerfPack {
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
