//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each non-stub rule has at least one positive (violating) and one
//! negative (clean) case. Stub rules have a registration-only test.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::cloudformation_no_drift_detection::CloudformationNoDriftDetectionRule;
use crate::compose_default_network::ComposeDefaultNetworkRule;
use crate::dockerfile_apt_no_clean::DockerfileAptNoCleanRule;
use crate::dockerfile_latest_tag::DockerfileLatestTagRule;
use crate::dockerfile_no_user::DockerfileNoUserRule;
use crate::helm_no_chart_lock::HelmNoChartLockRule;
use crate::k8s_no_resource_limits::K8sNoResourceLimitsRule;
use crate::k8s_no_security_context::K8sNoSecurityContextRule;
use crate::terraform_no_lifecycle_protection::TerraformNoLifecycleProtectionRule;
use crate::workflow_inline_secret::WorkflowInlineSecretRule;
use crate::BuiltinIacPack;

// ---------- shared fixtures -----------------------------------------------

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

    fn with_file(mut self, path: &str) -> Self {
        push_file(&mut self.batch, path);
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

// ---------- dockerfile_no_user --------------------------------------------

#[test]
fn dockerfile_no_user_flags_missing_directive() {
    let bytes = b"FROM alpine:3.20\nRUN apk add curl\nCMD [\"./app\"]\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    let findings = DockerfileNoUserRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.iac.dockerfile_no_user");
}

#[test]
fn dockerfile_no_user_silent_when_user_set() {
    let bytes = b"FROM alpine:3.20\nUSER appuser\nCMD [\"./app\"]\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    assert!(DockerfileNoUserRule.run(&fx.ctx()).is_empty());
}

// ---------- dockerfile_latest_tag -----------------------------------------

#[test]
fn dockerfile_latest_tag_flags_latest() {
    let bytes = b"FROM alpine:latest\nCMD [\"./app\"]\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    let findings = DockerfileLatestTagRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn dockerfile_latest_tag_silent_when_pinned() {
    let bytes = b"FROM alpine:3.20.0\nCMD [\"./app\"]\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    assert!(DockerfileLatestTagRule.run(&fx.ctx()).is_empty());
}

#[test]
fn dockerfile_latest_tag_silent_when_digest_pinned() {
    let bytes = b"FROM alpine@sha256:beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef\nCMD [\"./app\"]\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    assert!(DockerfileLatestTagRule.run(&fx.ctx()).is_empty());
}

// ---------- dockerfile_apt_no_clean ---------------------------------------

#[test]
fn dockerfile_apt_no_clean_flags_missing_clean() {
    let bytes = b"FROM ubuntu:22.04\nRUN apt-get install -y curl\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    let findings = DockerfileAptNoCleanRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn dockerfile_apt_no_clean_silent_when_cleaned() {
    let bytes =
        b"FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n".to_vec();
    let fx = Fixture::new()
        .with_source("Dockerfile", bytes)
        .with_file("Dockerfile");
    assert!(DockerfileAptNoCleanRule.run(&fx.ctx()).is_empty());
}

// ---------- k8s_no_resource_limits ----------------------------------------

#[test]
fn k8s_no_resource_limits_flags_unbounded_deployment() {
    let bytes = b"\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("deploy.yaml", bytes)
        .with_file("deploy.yaml");
    let findings = K8sNoResourceLimitsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn k8s_no_resource_limits_silent_when_limits_present() {
    let bytes = b"\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27
        resources:
          limits:
            cpu: 500m
            memory: 256Mi
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("deploy.yaml", bytes)
        .with_file("deploy.yaml");
    assert!(K8sNoResourceLimitsRule.run(&fx.ctx()).is_empty());
}

// ---------- k8s_no_security_context ---------------------------------------

#[test]
fn k8s_no_security_context_flags_missing_runasnonroot() {
    let bytes = b"\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("deploy.yaml", bytes)
        .with_file("deploy.yaml");
    let findings = K8sNoSecurityContextRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn k8s_no_security_context_silent_when_set() {
    let bytes = b"\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
      - name: web
        image: nginx:1.27
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("deploy.yaml", bytes)
        .with_file("deploy.yaml");
    assert!(K8sNoSecurityContextRule.run(&fx.ctx()).is_empty());
}

// ---------- terraform_no_lifecycle_protection -----------------------------

#[test]
fn terraform_no_lifecycle_protection_flags_unprotected_db() {
    let bytes = b"\
resource \"aws_db_instance\" \"main\" {
  engine = \"postgres\"
  instance_class = \"db.t3.micro\"
}
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("rds.tf", bytes)
        .with_file("rds.tf");
    let findings = TerraformNoLifecycleProtectionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn terraform_no_lifecycle_protection_silent_when_protected() {
    let bytes = b"\
resource \"aws_db_instance\" \"main\" {
  engine = \"postgres\"
  lifecycle {
    prevent_destroy = true
  }
}
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("rds.tf", bytes)
        .with_file("rds.tf");
    assert!(TerraformNoLifecycleProtectionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn terraform_no_lifecycle_protection_silent_for_low_risk_resource() {
    let bytes = b"\
resource \"aws_iam_role\" \"main\" {
  name = \"role\"
}
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("iam.tf", bytes)
        .with_file("iam.tf");
    assert!(TerraformNoLifecycleProtectionRule.run(&fx.ctx()).is_empty());
}

// ---------- helm_no_chart_lock --------------------------------------------

#[test]
fn helm_no_chart_lock_flags_missing_lock() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "charts/web/Chart.yaml");
    let findings = HelmNoChartLockRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn helm_no_chart_lock_silent_when_lock_present() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "charts/web/Chart.yaml");
    push_file(&mut fx.batch, "charts/web/Chart.lock");
    assert!(HelmNoChartLockRule.run(&fx.ctx()).is_empty());
}

// ---------- compose_default_network ---------------------------------------

#[test]
fn compose_default_network_flags_missing_networks() {
    let bytes = b"\
services:
  web:
    image: nginx:1.27
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("docker-compose.yml", bytes)
        .with_file("docker-compose.yml");
    let findings = ComposeDefaultNetworkRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

#[test]
fn compose_default_network_silent_when_explicit() {
    let bytes = b"\
services:
  web:
    image: nginx:1.27
networks:
  backend: {}
"
    .to_vec();
    let fx = Fixture::new()
        .with_source("docker-compose.yml", bytes)
        .with_file("docker-compose.yml");
    assert!(ComposeDefaultNetworkRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs ---------------------------------------------------------

#[test]
fn cloudformation_no_drift_detection_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(CloudformationNoDriftDetectionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn workflow_inline_secret_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(WorkflowInlineSecretRule.run(&fx.ctx()).is_empty());
}

// ---------- v12 self-host gate -------------------------------------------

#[test]
fn workflow_does_not_false_positive_on_v12_kernel_workflow() {
    // The kernel ships `.github/workflows/cc-check.yml`. Phase-6 stubs
    // the workflow-secret detector — make sure it stays silent.
    let fx = Fixture::new().with_file(".github/workflows/cc-check.yml");
    assert!(WorkflowInlineSecretRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_phase6_and_phase8_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinIacPack)
        .expect("Family-29 pack registers without error");
    assert_eq!(reg.rules().count(), BuiltinIacPack::PACK_RULE_COUNT);
    for slug in [
        // Phase 6 originals.
        "cc.iac.dockerfile_no_user",
        "cc.iac.dockerfile_latest_tag",
        "cc.iac.dockerfile_apt_no_clean",
        "cc.iac.k8s_no_resource_limits",
        "cc.iac.k8s_no_security_context",
        "cc.iac.terraform_no_lifecycle_protection",
        "cc.iac.helm_no_chart_lock",
        "cc.iac.cloudformation_no_drift_detection",
        "cc.iac.compose_default_network",
        "cc.iac.workflow_inline_secret",
        // Phase 8 additions.
        "cc.deploy.tf_unrestricted_ssh",
        "cc.deploy.tf_unencrypted_storage",
        "cc.deploy.tf_overpermissive_iam",
        "cc.deploy.tf_public_s3_bucket",
        "cc.deploy.tf_no_state_encryption",
        "cc.deploy.k8s_run_as_root",
        "cc.deploy.k8s_latest_tag",
        "cc.deploy.k8s_writable_root_fs",
        "cc.deploy.k8s_privileged",
        "cc.deploy.k8s_host_network",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
