//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each non-stub rule has at least one positive (violating) and one
//! negative (clean) case. Stub rules have a registration-only test.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

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
use crate::BuiltinSecretsPack;

// ---------- shared fixtures -----------------------------------------------

const SAMPLE_PATH: &str = "src/sample.py";

fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("python".into())),
    )
}

fn push_literal(batch: &mut CpgWriteBatch, parent: NodeId, value: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Literal)
            .with_prop("value", Value::String(value.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

struct Fixture {
    batch: CpgWriteBatch,
    source: InMemorySourceTable,
    config: RuleConfig,
    project: ProjectFingerprint,
    kernel: KernelMeta,
}

impl Fixture {
    fn new() -> Self {
        Self {
            batch: CpgWriteBatch::new(),
            source: InMemorySourceTable::new(),
            config: RuleConfig::default(),
            project: ProjectFingerprint::empty(),
            kernel: KernelMeta::now(),
        }
    }

    fn with_source(self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.source.insert(Utf8PathBuf::from(path), bytes);
        self
    }

    fn ctx(&self) -> RuleContext<'_> {
        RuleContext {
            batch: &self.batch,
            source: &self.source,
            config: &self.config,
            project: &self.project,
            kernel: &self.kernel,
        }
    }
}

// ---------- secret_in_code ------------------------------------------------

#[test]
fn secret_in_code_flags_aws_access_key() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_literal(
        &mut fx.batch,
        file,
        "AKIAIOSFODNN7EXAMPLE",
        range(1, 1, 0, 20),
    );
    let findings = SecretInCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.secret_in_code");
}

#[test]
fn secret_in_code_flags_github_pat() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_literal(
        &mut fx.batch,
        file,
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        range(1, 1, 0, 40),
    );
    assert_eq!(SecretInCodeRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn secret_in_code_flags_jwt() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_literal(
        &mut fx.batch,
        file,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        range(1, 1, 0, 60),
    );
    assert_eq!(SecretInCodeRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn secret_in_code_flags_private_key_header() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_literal(
        &mut fx.batch,
        file,
        "-----BEGIN RSA PRIVATE KEY-----",
        range(1, 1, 0, 31),
    );
    assert_eq!(SecretInCodeRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn secret_in_code_silent_on_innocuous_string() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_literal(&mut fx.batch, file, "hello, world", range(1, 1, 0, 12));
    assert!(SecretInCodeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn secret_in_code_silent_in_test_file() {
    // The same canonical AWS-example token in a tests/ path must NOT fire.
    let test_path = "tests/fixtures/secrets.py";
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, test_path);
    push_literal(
        &mut fx.batch,
        file,
        "AKIAIOSFODNN7EXAMPLE",
        range(1, 1, 0, 20),
    );
    assert!(SecretInCodeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn secret_in_code_flags_generic_under_credential_assignment() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let write = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String("api_key".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 80))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, write, file)
        .unwrap();
    push_literal(
        &mut fx.batch,
        write,
        "Z9p4Q1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aBc",
        range(1, 1, 5, 53),
    );
    assert_eq!(SecretInCodeRule.run(&fx.ctx()).len(), 1);
}

// ---------- weak_crypto ---------------------------------------------------

#[test]
fn weak_crypto_flags_hashlib_md5() {
    let bytes = b"import hashlib\nh = hashlib.md5(payload)\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "hashlib.md5", range(2, 2, 19, 30));
    let findings = WeakCryptoRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.weak_crypto");
}

#[test]
fn weak_crypto_silent_on_sha256() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "hashlib.sha256", range(1, 1, 0, 14));
    assert!(WeakCryptoRule.run(&fx.ctx()).is_empty());
}

#[test]
fn weak_crypto_silent_when_marked_non_security() {
    // `non-security` comment in the surrounding 3 lines suppresses the rule.
    let bytes = b"# non-security cache key - fast hash only\nh = hashlib.md5(payload)\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_call(&mut fx.batch, file, "hashlib.md5", range(2, 2, 42, 53));
    assert!(WeakCryptoRule.run(&fx.ctx()).is_empty());
}

// ---------- dotenv_lint ---------------------------------------------------

#[test]
fn dotenv_lint_flags_duplicate_key() {
    let bytes = b"FOO=bar\nFOO=baz\n".to_vec();
    let path = ".env";
    let mut fx = Fixture::new().with_source(path, bytes);
    push_file(&mut fx.batch, path);
    let findings = DotenvLintRule.run(&fx.ctx());
    assert!(
        findings
            .iter()
            .any(|f| f.message.headline.contains("duplicate")),
        "expected duplicate-key finding; got {findings:?}"
    );
}

#[test]
fn dotenv_lint_silent_on_clean_dotenv() {
    let bytes = b"FOO=bar\nBAZ=\"with spaces\"\n# comment\n".to_vec();
    let path = ".env";
    let mut fx = Fixture::new().with_source(path, bytes);
    push_file(&mut fx.batch, path);
    let findings = DotenvLintRule.run(&fx.ctx());
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn dotenv_lint_flags_lowercase_key() {
    let bytes = b"foo=bar\n".to_vec();
    let path = ".env";
    let mut fx = Fixture::new().with_source(path, bytes);
    push_file(&mut fx.batch, path);
    let findings = DotenvLintRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.headline.contains("lowercase"));
}

// ---------- dead_env_var --------------------------------------------------

#[test]
fn dead_env_var_flags_unreferenced_env_lookup() {
    let bytes = b"value = os.environ.get(\"ORPHAN_VAR\")\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String("os.environ.get".into()))
            .with_prop("first_arg_value", Value::String("ORPHAN_VAR".into()))
            .with_prop("range", Value::Range(range(1, 1, 8, 36))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = DeadEnvVarRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].message.headline.contains("ORPHAN_VAR"));
}

#[test]
fn dead_env_var_silent_when_name_appears_elsewhere() {
    let bytes = b"# the LIVE_VAR drives behaviour\nvalue = os.environ.get(\"LIVE_VAR\")\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String("os.environ.get".into()))
            .with_prop("first_arg_value", Value::String("LIVE_VAR".into()))
            .with_prop("range", Value::Range(range(2, 2, 30, 65))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    assert!(DeadEnvVarRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs ---------------------------------------------------------

#[test]
fn dead_config_key_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(DeadConfigKeyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn env_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(EnvDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- Phase-8 source-byte probes -----------------------------------

const PY_PATH: &str = "src/sample.py";
const TXT_PATH: &str = "src/sample.txt";

fn fixture_for_bytes(path: &str, bytes: impl Into<Vec<u8>>) -> Fixture {
    let mut fx = Fixture::new().with_source(path, bytes);
    push_file(&mut fx.batch, path);
    fx
}

#[test]
fn aws_token_pattern_flags_akia_in_yaml() {
    let bytes = b"key: AKIAIOSFODNN7EXAMPLE\n".to_vec();
    let fx = fixture_for_bytes("src/sample.yaml", bytes);
    let findings = AwsTokenPatternRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.aws_token_pattern");
}

#[test]
fn aws_token_pattern_flags_asia_session_key() {
    let bytes = b"prod = ASIAY34FZKBOKMUTVV7A\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(AwsTokenPatternRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn aws_token_pattern_silent_in_fixture_dir() {
    let bytes = b"AKIAIOSFODNN7EXAMPLE\n".to_vec();
    let fx = fixture_for_bytes("tests/fixtures/aws.txt", bytes);
    assert!(AwsTokenPatternRule.run(&fx.ctx()).is_empty());
}

#[test]
fn aws_token_pattern_silent_on_doc_extension() {
    let bytes = b"## Example\nAKIAIOSFODNN7EXAMPLE\n".to_vec();
    let fx = fixture_for_bytes(TXT_PATH, bytes);
    assert!(AwsTokenPatternRule.run(&fx.ctx()).is_empty());
}

#[test]
fn private_key_pem_flags_rsa_header() {
    let bytes = b"# config\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n".to_vec();
    let fx = fixture_for_bytes("src/cred.pem", bytes);
    let findings = PrivateKeyPemRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn private_key_pem_flags_openssh_header() {
    let bytes = b"-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n".to_vec();
    let fx = fixture_for_bytes("src/k.pem", bytes);
    assert_eq!(PrivateKeyPemRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn private_key_pem_silent_on_public_key_header() {
    let bytes = b"-----BEGIN PUBLIC KEY-----\nbody\n".to_vec();
    let fx = fixture_for_bytes("src/k.pem", bytes);
    assert!(PrivateKeyPemRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gcp_api_key_flags_aiza_token() {
    let bytes = b"key = \"AIzaSyA-1234567890abcdefghijklmnopqrstuvwx\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(GcpApiKeyRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gcp_api_key_silent_on_short_aiza_prefix() {
    let bytes = b"AIzaShort\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(GcpApiKeyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gcp_api_key_silent_in_md_doc() {
    let bytes = b"# example\nAIzaSyA-1234567890abcdefghijklmnopqrstuvwx\n".to_vec();
    let fx = fixture_for_bytes("README.md", bytes);
    assert!(GcpApiKeyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn github_pat_flags_classic_token() {
    let bytes = b"token = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(GithubPatRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn github_pat_flags_fine_grained_token() {
    let mut tail = vec![b'A'; 82];
    let mut bytes = b"x = \"github_pat_".to_vec();
    bytes.append(&mut tail);
    bytes.push(b'"');
    bytes.push(b'\n');
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(GithubPatRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn github_pat_silent_on_short_prefix() {
    let bytes = b"ghp_short\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(GithubPatRule.run(&fx.ctx()).is_empty());
}

#[test]
fn slack_token_flags_xoxb_token() {
    let bytes = b"slack = \"xoxb-1234567890-abcdefg\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(SlackTokenRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn slack_token_silent_on_unknown_kind_byte() {
    // `xoxz-` is not a valid kind byte.
    let bytes = b"slack = \"xoxz-1234567890abcdef\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(SlackTokenRule.run(&fx.ctx()).is_empty());
}

#[test]
fn slack_token_silent_in_corpus() {
    let bytes = b"xoxb-1234567890-abcdefg\n".to_vec();
    let fx = fixture_for_bytes("corpus/leak.txt", bytes);
    assert!(SlackTokenRule.run(&fx.ctx()).is_empty());
}

#[test]
fn stripe_key_flags_sk_live() {
    let bytes = b"k = \"sk_live_abcdefghijklmnopqrstuvwx\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    let findings = StripeKeyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert!(findings[0].message.headline.contains("secret"));
}

#[test]
fn stripe_key_flags_pk_live() {
    let bytes = b"k = \"pk_live_abcdefghijklmnopqrstuvwx\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    let findings = StripeKeyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.headline.contains("publishable"));
}

#[test]
fn stripe_key_silent_on_test_prefix() {
    let bytes = b"k = \"sk_test_abcdefghijklmnopqrstuvwx\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(StripeKeyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn generic_api_key_assignment_flags_long_secret_string() {
    let bytes = b"api_key = \"abcdef0123456789abcdef\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(GenericApiKeyAssignmentRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn generic_api_key_assignment_silent_on_short_value() {
    let bytes = b"api_key = \"short\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(GenericApiKeyAssignmentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn generic_api_key_assignment_silent_on_passwordless_word() {
    // Word-boundary check: `passwordless_token` should not match `password`.
    let bytes = b"passwordless_flag = \"shortvalue\"\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(GenericApiKeyAssignmentRule.run(&fx.ctx()).is_empty());
}

#[test]
fn requests_no_verify_flags_get_with_verify_false() {
    let bytes = b"r = requests.get(\"https://x\", verify=False)\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(RequestsNoVerifyRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn requests_no_verify_silent_on_default_verify() {
    let bytes = b"r = requests.get(\"https://x\")\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(RequestsNoVerifyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn requests_no_verify_silent_outside_python_file() {
    let bytes = b"r = requests.get(\"https://x\", verify=False)\n".to_vec();
    let fx = fixture_for_bytes("src/sample.js", bytes);
    assert!(RequestsNoVerifyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn subprocess_shell_true_flags_string_command() {
    let bytes = b"subprocess.run(\"ls -la\", shell=True)\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(SubprocessShellTrueRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn subprocess_shell_true_silent_on_list_command() {
    // List form is safe and ignored.
    let bytes = b"subprocess.run([\"ls\", \"-la\"], shell=True)\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(SubprocessShellTrueRule.run(&fx.ctx()).is_empty());
}

#[test]
fn subprocess_shell_true_silent_on_default_shell() {
    let bytes = b"subprocess.run(\"ls -la\")\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(SubprocessShellTrueRule.run(&fx.ctx()).is_empty());
}

#[test]
fn urllib_no_verify_flags_unverified_context() {
    let bytes = b"ctx = ssl._create_unverified_context()\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(UrllibNoVerifyRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn urllib_no_verify_flags_cert_none_assignment() {
    let bytes = b"ctx = ssl.SSLContext()\nctx.verify_mode = ssl.CERT_NONE\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert_eq!(UrllibNoVerifyRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn urllib_no_verify_silent_on_default_context() {
    let bytes = b"ctx = ssl.create_default_context()\n".to_vec();
    let fx = fixture_for_bytes(PY_PATH, bytes);
    assert!(UrllibNoVerifyRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_all_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinSecretsPack)
        .expect("Family-19 pack registers without error");
    assert_eq!(reg.rules().count(), 21);
    for slug in [
        "cc.config.secret_in_code",
        "cc.config.dead_env_var",
        "cc.config.dead_config_key",
        "cc.config.env_drift",
        "cc.config.weak_crypto",
        "cc.config.dotenv_lint",
        "cc.config.aws_token_pattern",
        "cc.config.private_key_pem",
        "cc.config.gcp_api_key",
        "cc.config.github_pat",
        "cc.config.slack_token",
        "cc.config.stripe_key",
        "cc.config.generic_api_key_assignment",
        "cc.config.requests_no_verify",
        "cc.config.subprocess_shell_true",
        "cc.config.urllib_no_verify",
        "cc.config.gosec_hardcoded_creds_var",
        "cc.config.gosec_weak_random",
        "cc.config.gosec_md5_sha1",
        "cc.config.gosec_des_rc4",
        "cc.config.gosec_tls_insecure_skip_verify",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

// ---------- Phase-10 gosec probes ----------------------------------------

const GO_PATH: &str = "src/sample.go";

#[test]
fn gosec_hardcoded_creds_var_flags_var_with_long_literal() {
    let bytes = b"package main\nvar APIKey = \"abcdef0123456789ZYXW\"\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    let findings = GosecHardcodedCredsVarRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.gosec_hardcoded_creds_var");
}

#[test]
fn gosec_hardcoded_creds_var_silent_on_short_value() {
    let bytes = b"package main\nvar APIKey = \"short\"\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecHardcodedCredsVarRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_hardcoded_creds_var_silent_on_test_placeholder() {
    let bytes = b"package main\nconst Token = \"test_abcdef0123456789zyxw\"\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecHardcodedCredsVarRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_hardcoded_creds_var_silent_in_go_test_file() {
    let bytes = b"package main\nvar APIKey = \"abcdef0123456789ZYXW\"\n".to_vec();
    let fx = fixture_for_bytes("src/sample_test.go", bytes);
    assert!(GosecHardcodedCredsVarRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_weak_random_flags_rand_int_for_token() {
    let bytes =
        b"package main\nimport \"math/rand\"\nfunc f() int { token := rand.Int(); return token }\n"
            .to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    let findings = GosecWeakRandomRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.gosec_weak_random");
}

#[test]
fn gosec_weak_random_silent_when_no_security_keyword() {
    let bytes =
        b"package main\nimport \"math/rand\"\nfunc f() { dice := rand.Intn(6); _ = dice }\n"
            .to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecWeakRandomRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_weak_random_silent_when_only_crypto_rand_imported() {
    let bytes = b"package main\nimport \"crypto/rand\"\nfunc f() { _, _ = rand.Read(make([]byte, 32)); _ = \"token\" }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecWeakRandomRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_md5_sha1_flags_md5_for_signature() {
    let bytes = b"package main\nimport \"crypto/md5\"\nfunc sign() { signature := md5.Sum(payload); _ = signature }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    let findings = GosecMd5Sha1Rule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.gosec_md5_sha1");
}

#[test]
fn gosec_md5_sha1_flags_sha1_for_password() {
    let bytes = b"package main\nimport \"crypto/sha1\"\nfunc f() { password := input; h := sha1.New(); _ = h }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert_eq!(GosecMd5Sha1Rule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gosec_md5_sha1_silent_when_no_security_keyword() {
    let bytes = b"package main\nimport \"crypto/md5\"\nfunc fingerprint(b []byte) [16]byte { return md5.Sum(b) }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecMd5Sha1Rule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_des_rc4_flags_des_new_cipher() {
    let bytes =
        b"package main\nimport \"crypto/des\"\nfunc f() { c, _ := des.NewCipher(key); _ = c }\n"
            .to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    let findings = GosecDesRc4Rule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.config.gosec_des_rc4");
}

#[test]
fn gosec_des_rc4_flags_rc4_new_cipher() {
    let bytes =
        b"package main\nimport \"crypto/rc4\"\nfunc f() { c, _ := rc4.NewCipher(key); _ = c }\n"
            .to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert_eq!(GosecDesRc4Rule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gosec_des_rc4_silent_on_aes() {
    let bytes =
        b"package main\nimport \"crypto/aes\"\nfunc f() { c, _ := aes.NewCipher(key); _ = c }\n"
            .to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecDesRc4Rule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_tls_insecure_skip_verify_flags_true_assignment() {
    let bytes = b"package main\nimport \"crypto/tls\"\nfunc f() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    let findings = GosecTlsInsecureSkipVerifyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.config.gosec_tls_insecure_skip_verify"
    );
}

#[test]
fn gosec_tls_insecure_skip_verify_silent_on_false() {
    let bytes =
        b"package main\nfunc f() { c := tls.Config{InsecureSkipVerify: false}; _ = c }\n".to_vec();
    let fx = fixture_for_bytes(GO_PATH, bytes);
    assert!(GosecTlsInsecureSkipVerifyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_tls_insecure_skip_verify_silent_in_test_file() {
    let bytes =
        b"package main\nfunc f() { c := tls.Config{InsecureSkipVerify: true}; _ = c }\n".to_vec();
    let fx = fixture_for_bytes("src/x_test.go", bytes);
    assert!(GosecTlsInsecureSkipVerifyRule.run(&fx.ctx()).is_empty());
}
