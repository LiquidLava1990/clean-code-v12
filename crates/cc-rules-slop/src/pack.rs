//! [`BuiltinSlopPack`] — registers the eight Family-1 slop rules.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::comment_vs_code::CommentVsCodeRule;
use crate::defensive_pure_fn::DefensivePureFnRule;
use crate::drift_from_project::DriftFromProjectRule;
use crate::fake_thoughtful_name::FakeThoughtfulNameRule;
use crate::llm_texture::LlmTextureRule;
use crate::over_commented_obvious::OverCommentedObviousRule;
use crate::premature_abstraction::PrematureAbstractionRule;
use crate::unused_helper::UnusedHelperRule;

/// Built-in Family-1 [`RulePack`] — eight slop & drift rules.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinSlopPack;

impl BuiltinSlopPack {
    /// Stable pack id. Distinct from the Tier-0 pack so the kernel
    /// registers both side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-slop";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static COMMENT_VS_CODE: CommentVsCodeRule = CommentVsCodeRule;
static FAKE_THOUGHTFUL_NAME: FakeThoughtfulNameRule = FakeThoughtfulNameRule;
static OVER_COMMENTED_OBVIOUS: OverCommentedObviousRule = OverCommentedObviousRule;
static DEFENSIVE_PURE_FN: DefensivePureFnRule = DefensivePureFnRule;
static UNUSED_HELPER: UnusedHelperRule = UnusedHelperRule;
static PREMATURE_ABSTRACTION: PrematureAbstractionRule = PrematureAbstractionRule;
static DRIFT_FROM_PROJECT: DriftFromProjectRule = DriftFromProjectRule;
static LLM_TEXTURE: LlmTextureRule = LlmTextureRule;

static RULES: &[&'static dyn Rule] = &[
    &COMMENT_VS_CODE,
    &FAKE_THOUGHTFUL_NAME,
    &OVER_COMMENTED_OBVIOUS,
    &DEFENSIVE_PURE_FN,
    &UNUSED_HELPER,
    &PREMATURE_ABSTRACTION,
    &DRIFT_FROM_PROJECT,
    &LLM_TEXTURE,
];

impl RulePack for BuiltinSlopPack {
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
