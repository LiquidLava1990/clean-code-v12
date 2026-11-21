//! [`BuiltinSupplyChainPack`] — registers the ten Family-32 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::action_version_skew::ActionVersionSkewRule;
use crate::cargo_unpinned_git_dep::CargoUnpinnedGitDepRule;
use crate::dangerous_workflow_pr_target::DangerousWorkflowPrTargetRule;
use crate::docker_apk_no_pin::DockerApkNoPinRule;
use crate::no_codeowners::NoCodeownersRule;
use crate::no_dependabot_config::NoDependabotConfigRule;
use crate::no_security_md::NoSecurityMdRule;
use crate::npm_dangerous_install_script::NpmDangerousInstallScriptRule;
use crate::npm_outdated_majors::NpmOutdatedMajorsRule;
use crate::unpinned_action::UnpinnedActionRule;

/// Built-in Family-32 [`RulePack`] — ten probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinSupplyChainPack;

impl BuiltinSupplyChainPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-supplychain";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static UNPINNED_ACTION: UnpinnedActionRule = UnpinnedActionRule;
static DANGEROUS_WORKFLOW_PR_TARGET: DangerousWorkflowPrTargetRule = DangerousWorkflowPrTargetRule;
static NO_DEPENDABOT_CONFIG: NoDependabotConfigRule = NoDependabotConfigRule;
static NO_CODEOWNERS: NoCodeownersRule = NoCodeownersRule;
static NO_SECURITY_MD: NoSecurityMdRule = NoSecurityMdRule;
static NPM_OUTDATED_MAJORS: NpmOutdatedMajorsRule = NpmOutdatedMajorsRule;
static CARGO_UNPINNED_GIT_DEP: CargoUnpinnedGitDepRule = CargoUnpinnedGitDepRule;
static NPM_DANGEROUS_INSTALL_SCRIPT: NpmDangerousInstallScriptRule = NpmDangerousInstallScriptRule;
static DOCKER_APK_NO_PIN: DockerApkNoPinRule = DockerApkNoPinRule;
static ACTION_VERSION_SKEW: ActionVersionSkewRule = ActionVersionSkewRule;

static RULES: &[&'static dyn Rule] = &[
    &UNPINNED_ACTION,
    &DANGEROUS_WORKFLOW_PR_TARGET,
    &NO_DEPENDABOT_CONFIG,
    &NO_CODEOWNERS,
    &NO_SECURITY_MD,
    &NPM_OUTDATED_MAJORS,
    &CARGO_UNPINNED_GIT_DEP,
    &NPM_DANGEROUS_INSTALL_SCRIPT,
    &DOCKER_APK_NO_PIN,
    &ACTION_VERSION_SKEW,
];

impl RulePack for BuiltinSupplyChainPack {
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
