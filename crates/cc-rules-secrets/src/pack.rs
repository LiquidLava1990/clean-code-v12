//! [`BuiltinSecretsPack`] — registers every Family-19 probe.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::aws_token_pattern::AwsTokenPatternRule;
use crate::dead_config_key::DeadConfigKeyRule;
use crate::dead_env_var::DeadEnvVarRule;
use crate::dotenv_lint::DotenvLintRule;
use crate::env_drift::EnvDriftRule;
use crate::gcp_api_key::GcpApiKeyRule;
use crate::generic_api_key_assignment::GenericApiKeyAssignmentRule;
use crate::github_pat::GithubPatRule;
use crate::gosec_des_rc4::GosecDesRc4Rule;
use crate::gosec_hardcoded_creds_var::GosecHardcodedCredsVarRule;
use crate::gosec_md5_sha1::GosecMd5Sha1Rule;
use crate::gosec_tls_insecure_skip_verify::GosecTlsInsecureSkipVerifyRule;
use crate::gosec_weak_random::GosecWeakRandomRule;
use crate::private_key_pem::PrivateKeyPemRule;
use crate::requests_no_verify::RequestsNoVerifyRule;
use crate::secret_in_code::SecretInCodeRule;
use crate::slack_token::SlackTokenRule;
use crate::stripe_key::StripeKeyRule;
use crate::subprocess_shell_true::SubprocessShellTrueRule;
use crate::urllib_no_verify::UrllibNoVerifyRule;
use crate::weak_crypto::WeakCryptoRule;

/// Built-in Family-19 [`RulePack`] — every Phase-2 + Phase-8 probe in
/// one registry-registerable bundle.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinSecretsPack;

impl BuiltinSecretsPack {
    /// Stable pack id. Distinct from `cc-builtin-tier0` so the registry
    /// can host both side-by-side without colliding.
    pub const PACK_ID: &'static str = "cc-builtin-secrets";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static SECRET_IN_CODE: SecretInCodeRule = SecretInCodeRule;
static DEAD_ENV_VAR: DeadEnvVarRule = DeadEnvVarRule;
static DEAD_CONFIG_KEY: DeadConfigKeyRule = DeadConfigKeyRule;
static ENV_DRIFT: EnvDriftRule = EnvDriftRule;
static WEAK_CRYPTO: WeakCryptoRule = WeakCryptoRule;
static DOTENV_LINT: DotenvLintRule = DotenvLintRule;
static AWS_TOKEN_PATTERN: AwsTokenPatternRule = AwsTokenPatternRule;
static PRIVATE_KEY_PEM: PrivateKeyPemRule = PrivateKeyPemRule;
static GCP_API_KEY: GcpApiKeyRule = GcpApiKeyRule;
static GITHUB_PAT: GithubPatRule = GithubPatRule;
static SLACK_TOKEN: SlackTokenRule = SlackTokenRule;
static STRIPE_KEY: StripeKeyRule = StripeKeyRule;
static GENERIC_API_KEY_ASSIGNMENT: GenericApiKeyAssignmentRule = GenericApiKeyAssignmentRule;
static REQUESTS_NO_VERIFY: RequestsNoVerifyRule = RequestsNoVerifyRule;
static SUBPROCESS_SHELL_TRUE: SubprocessShellTrueRule = SubprocessShellTrueRule;
static URLLIB_NO_VERIFY: UrllibNoVerifyRule = UrllibNoVerifyRule;
static GOSEC_HARDCODED_CREDS_VAR: GosecHardcodedCredsVarRule = GosecHardcodedCredsVarRule;
static GOSEC_WEAK_RANDOM: GosecWeakRandomRule = GosecWeakRandomRule;
static GOSEC_MD5_SHA1: GosecMd5Sha1Rule = GosecMd5Sha1Rule;
static GOSEC_DES_RC4: GosecDesRc4Rule = GosecDesRc4Rule;
static GOSEC_TLS_INSECURE_SKIP_VERIFY: GosecTlsInsecureSkipVerifyRule =
    GosecTlsInsecureSkipVerifyRule;

static RULES: &[&'static dyn Rule] = &[
    &SECRET_IN_CODE,
    &DEAD_ENV_VAR,
    &DEAD_CONFIG_KEY,
    &ENV_DRIFT,
    &WEAK_CRYPTO,
    &DOTENV_LINT,
    &AWS_TOKEN_PATTERN,
    &PRIVATE_KEY_PEM,
    &GCP_API_KEY,
    &GITHUB_PAT,
    &SLACK_TOKEN,
    &STRIPE_KEY,
    &GENERIC_API_KEY_ASSIGNMENT,
    &REQUESTS_NO_VERIFY,
    &SUBPROCESS_SHELL_TRUE,
    &URLLIB_NO_VERIFY,
    &GOSEC_HARDCODED_CREDS_VAR,
    &GOSEC_WEAK_RANDOM,
    &GOSEC_MD5_SHA1,
    &GOSEC_DES_RC4,
    &GOSEC_TLS_INSECURE_SKIP_VERIFY,
];

impl RulePack for BuiltinSecretsPack {
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
