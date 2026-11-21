//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real probe has at least one positive (violating) and one
//! negative (clean) case. Each stub has a registration-only test. The
//! pack-level test confirms all ten rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

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
use crate::BuiltinSupplyChainPack;

// ---------- shared fixtures ----------------------------------------------

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("yaml".into())),
    )
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

// ---------- unpinned_action ---------------------------------------------

#[test]
fn unpinned_action_flags_tag_ref() {
    let path = ".github/workflows/ci.yml";
    let body = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = UnpinnedActionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.unpinned_action");
}

#[test]
fn unpinned_action_silent_when_pinned_to_sha() {
    let path = ".github/workflows/ci.yml";
    let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
    let body = format!("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@{sha}\n");
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(UnpinnedActionRule.run(&fx.ctx()).is_empty());
}

// ---------- dangerous_workflow_pr_target --------------------------------

#[test]
fn dangerous_workflow_flags_pr_target_with_head_checkout() {
    let path = ".github/workflows/preview.yml";
    let body = "on: pull_request_target\n\
                jobs:\n  build:\n    steps:\n      \
                - uses: actions/checkout@v4\n        \
                with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = DangerousWorkflowPrTargetRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.supplychain.dangerous_workflow_pr_target"
    );
}

#[test]
fn dangerous_workflow_silent_on_plain_pull_request() {
    let path = ".github/workflows/test.yml";
    let body = "on: pull_request\n\
                jobs:\n  build:\n    steps:\n      \
                - uses: actions/checkout@v4\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(DangerousWorkflowPrTargetRule.run(&fx.ctx()).is_empty());
}

// ---------- no_dependabot_config ----------------------------------------

#[test]
fn no_dependabot_flags_repo_with_manifest_no_config() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    let findings = NoDependabotConfigRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.no_dependabot_config");
}

#[test]
fn no_dependabot_silent_when_config_present() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    push_file(&mut fx.batch, ".github/dependabot.yml");
    assert!(NoDependabotConfigRule.run(&fx.ctx()).is_empty());
}

// ---------- no_codeowners -----------------------------------------------

#[test]
fn no_codeowners_flags_repo_without_codeowners() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    let findings = NoCodeownersRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.no_codeowners");
}

#[test]
fn no_codeowners_silent_with_github_codeowners() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    push_file(&mut fx.batch, ".github/CODEOWNERS");
    assert!(NoCodeownersRule.run(&fx.ctx()).is_empty());
}

// ---------- no_security_md ----------------------------------------------

#[test]
fn no_security_md_flags_repo_without_security_policy() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    let findings = NoSecurityMdRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.no_security_md");
}

#[test]
fn no_security_md_silent_with_security_md() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "Cargo.toml");
    push_file(&mut fx.batch, "SECURITY.md");
    assert!(NoSecurityMdRule.run(&fx.ctx()).is_empty());
}

// ---------- cargo_unpinned_git_dep --------------------------------------

#[test]
fn cargo_unpinned_git_dep_flags_branch_only() {
    let path = "Cargo.toml";
    let body = "[dependencies]\nfoo = { git = \"https://example.com/foo\", branch = \"main\" }\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = CargoUnpinnedGitDepRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.cargo_unpinned_git_dep");
}

#[test]
fn cargo_unpinned_git_dep_silent_when_rev_pinned() {
    let path = "Cargo.toml";
    let body =
        "[dependencies]\nfoo = { git = \"https://example.com/foo\", rev = \"abc1234567\" }\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(CargoUnpinnedGitDepRule.run(&fx.ctx()).is_empty());
}

// ---------- npm_dangerous_install_script --------------------------------

#[test]
fn npm_dangerous_install_script_flags_postinstall() {
    let path = "package.json";
    let body = "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"postinstall\": \"node ./hook.js\"\n  }\n}\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = NpmDangerousInstallScriptRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.supplychain.npm_dangerous_install_script"
    );
}

#[test]
fn npm_dangerous_install_script_silent_when_only_build_script() {
    let path = "package.json";
    let body = "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"build\": \"tsc\"\n  }\n}\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(NpmDangerousInstallScriptRule.run(&fx.ctx()).is_empty());
}

// ---------- docker_apk_no_pin -------------------------------------------

#[test]
fn docker_apk_no_pin_flags_unpinned_pkg() {
    let path = "Dockerfile";
    let body = "FROM alpine:3.19\nRUN apk add --no-cache curl bash\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    let findings = DockerApkNoPinRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.supplychain.docker_apk_no_pin");
}

#[test]
fn docker_apk_no_pin_silent_when_pinned() {
    let path = "Dockerfile";
    let body = "FROM alpine:3.19\nRUN apk add --no-cache curl=8.5.0-r0 bash=5.2.21-r0\n";
    let mut fx = Fixture::new().with_source(path, body.as_bytes().to_vec());
    push_file(&mut fx.batch, path);
    assert!(DockerApkNoPinRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs -------------------------------------------------------

#[test]
fn npm_outdated_majors_is_stub_silent() {
    let fx = Fixture::new();
    assert!(NpmOutdatedMajorsRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        NpmOutdatedMajorsRule.rule_id(),
        "cc.supplychain.npm_outdated_majors"
    );
}

#[test]
fn action_version_skew_is_stub_silent() {
    let fx = Fixture::new();
    assert!(ActionVersionSkewRule.run(&fx.ctx()).is_empty());
    assert_eq!(
        ActionVersionSkewRule.rule_id(),
        "cc.supplychain.action_version_skew"
    );
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_ten_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinSupplyChainPack)
        .expect("Family-32 pack registers without error");
    assert_eq!(reg.rules().count(), 10);
    for slug in [
        "cc.supplychain.unpinned_action",
        "cc.supplychain.dangerous_workflow_pr_target",
        "cc.supplychain.no_dependabot_config",
        "cc.supplychain.no_codeowners",
        "cc.supplychain.no_security_md",
        "cc.supplychain.npm_outdated_majors",
        "cc.supplychain.cargo_unpinned_git_dep",
        "cc.supplychain.npm_dangerous_install_script",
        "cc.supplychain.docker_apk_no_pin",
        "cc.supplychain.action_version_skew",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
