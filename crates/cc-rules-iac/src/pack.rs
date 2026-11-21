//! [`BuiltinIacPack`] — registers the Family-29 probes (Phase 6 + Phase 8).

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::cloudformation_no_drift_detection::CloudformationNoDriftDetectionRule;
use crate::compose_default_network::ComposeDefaultNetworkRule;
use crate::dockerfile_apt_no_clean::DockerfileAptNoCleanRule;
use crate::dockerfile_latest_tag::DockerfileLatestTagRule;
use crate::dockerfile_no_user::DockerfileNoUserRule;
use crate::helm_no_chart_lock::HelmNoChartLockRule;
use crate::k8s_host_network::K8sHostNetworkRule;
use crate::k8s_latest_tag::K8sLatestTagRule;
use crate::k8s_no_resource_limits::K8sNoResourceLimitsRule;
use crate::k8s_no_security_context::K8sNoSecurityContextRule;
use crate::k8s_privileged::K8sPrivilegedRule;
use crate::k8s_run_as_root::K8sRunAsRootRule;
use crate::k8s_writable_root_fs::K8sWritableRootFsRule;
use crate::terraform_no_lifecycle_protection::TerraformNoLifecycleProtectionRule;
use crate::tf_no_state_encryption::TfNoStateEncryptionRule;
use crate::tf_overpermissive_iam::TfOverpermissiveIamRule;
use crate::tf_public_s3_bucket::TfPublicS3BucketRule;
use crate::tf_unencrypted_storage::TfUnencryptedStorageRule;
use crate::tf_unrestricted_ssh::TfUnrestrictedSshRule;
use crate::workflow_inline_secret::WorkflowInlineSecretRule;

/// Built-in Family-29 [`RulePack`] — Phase 6 ships ten probes, Phase 8
/// adds another ten Checkov + kube-linter hardening probes (twenty
/// total, all `Severity::Required`).
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinIacPack;

impl BuiltinIacPack {
    /// Stable pack id.
    pub const PACK_ID: &'static str = "cc-builtin-iac";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");

    /// Total registered probe count after Phase 8 (Phase 6 = 10, Phase 8 = +10).
    pub const PACK_RULE_COUNT: usize = 20;
}

// Phase-6 originals.
static DOCKERFILE_NO_USER: DockerfileNoUserRule = DockerfileNoUserRule;
static DOCKERFILE_LATEST_TAG: DockerfileLatestTagRule = DockerfileLatestTagRule;
static DOCKERFILE_APT_NO_CLEAN: DockerfileAptNoCleanRule = DockerfileAptNoCleanRule;
static K8S_NO_RESOURCE_LIMITS: K8sNoResourceLimitsRule = K8sNoResourceLimitsRule;
static K8S_NO_SECURITY_CONTEXT: K8sNoSecurityContextRule = K8sNoSecurityContextRule;
static TERRAFORM_NO_LIFECYCLE_PROTECTION: TerraformNoLifecycleProtectionRule =
    TerraformNoLifecycleProtectionRule;
static HELM_NO_CHART_LOCK: HelmNoChartLockRule = HelmNoChartLockRule;
static CLOUDFORMATION_NO_DRIFT_DETECTION: CloudformationNoDriftDetectionRule =
    CloudformationNoDriftDetectionRule;
static COMPOSE_DEFAULT_NETWORK: ComposeDefaultNetworkRule = ComposeDefaultNetworkRule;
static WORKFLOW_INLINE_SECRET: WorkflowInlineSecretRule = WorkflowInlineSecretRule;

// Phase-8 additions (Checkov + kube-linter).
static TF_UNRESTRICTED_SSH: TfUnrestrictedSshRule = TfUnrestrictedSshRule;
static TF_UNENCRYPTED_STORAGE: TfUnencryptedStorageRule = TfUnencryptedStorageRule;
static TF_OVERPERMISSIVE_IAM: TfOverpermissiveIamRule = TfOverpermissiveIamRule;
static TF_PUBLIC_S3_BUCKET: TfPublicS3BucketRule = TfPublicS3BucketRule;
static TF_NO_STATE_ENCRYPTION: TfNoStateEncryptionRule = TfNoStateEncryptionRule;
static K8S_RUN_AS_ROOT: K8sRunAsRootRule = K8sRunAsRootRule;
static K8S_LATEST_TAG: K8sLatestTagRule = K8sLatestTagRule;
static K8S_WRITABLE_ROOT_FS: K8sWritableRootFsRule = K8sWritableRootFsRule;
static K8S_PRIVILEGED: K8sPrivilegedRule = K8sPrivilegedRule;
static K8S_HOST_NETWORK: K8sHostNetworkRule = K8sHostNetworkRule;

static RULES: &[&'static dyn Rule] = &[
    // Phase 6.
    &DOCKERFILE_NO_USER,
    &DOCKERFILE_LATEST_TAG,
    &DOCKERFILE_APT_NO_CLEAN,
    &K8S_NO_RESOURCE_LIMITS,
    &K8S_NO_SECURITY_CONTEXT,
    &TERRAFORM_NO_LIFECYCLE_PROTECTION,
    &HELM_NO_CHART_LOCK,
    &CLOUDFORMATION_NO_DRIFT_DETECTION,
    &COMPOSE_DEFAULT_NETWORK,
    &WORKFLOW_INLINE_SECRET,
    // Phase 8.
    &TF_UNRESTRICTED_SSH,
    &TF_UNENCRYPTED_STORAGE,
    &TF_OVERPERMISSIVE_IAM,
    &TF_PUBLIC_S3_BUCKET,
    &TF_NO_STATE_ENCRYPTION,
    &K8S_RUN_AS_ROOT,
    &K8S_LATEST_TAG,
    &K8S_WRITABLE_ROOT_FS,
    &K8S_PRIVILEGED,
    &K8S_HOST_NETWORK,
];

impl RulePack for BuiltinIacPack {
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
