//! `cc-rules-iac` — Family 29 (Infrastructure-as-code + cloud config) probe pack.
//!
//! Phase 6 of Clean Code V12 shipped the original 10 IaC probes; Phase 8
//! extends the pack with 10 hardening probes mined from Checkov +
//! kube-linter (`OSS_LINTER_DELTA.md` Top-50). Each probe walks
//! [`cc_cpg::NodeKind::File`] nodes, identifies its target by basename /
//! path heuristic, then scans the source bytes for the expected
//! configuration shape. None of these probes parse YAML / HCL /
//! Dockerfile / TOML semantically — that work belongs to a frontend.
//!
//! Phase-6 probes:
//! - [`dockerfile_no_user`] — `Dockerfile` running as root.
//! - [`dockerfile_latest_tag`] — `FROM image:latest` / no tag.
//! - [`dockerfile_apt_no_clean`] — `apt-get install` without lists clean.
//! - [`k8s_no_resource_limits`] — k8s `Deployment` / `Pod` without `resources.limits`.
//! - [`k8s_no_security_context`] — k8s pod without `runAsNonRoot: true`.
//! - [`terraform_no_lifecycle_protection`] — high-risk TF resource without `prevent_destroy`.
//! - [`helm_no_chart_lock`] — `Chart.yaml` without adjacent `Chart.lock`.
//! - [`cloudformation_no_drift_detection`] — Phase-6 STUB.
//! - [`compose_default_network`] — `docker-compose.yml` without explicit `networks:`.
//! - [`workflow_inline_secret`] — Phase-6 STUB; defers to `cc.config.secret_in_code`.
//!
//! Phase-8 additions (Checkov + kube-linter Top-50):
//! - [`tf_unrestricted_ssh`] — security-group ingress 22 from 0.0.0.0/0 (CKV_AWS_24).
//! - [`tf_unencrypted_storage`] — EBS / S3 / RDS missing encryption-at-rest (CKV_AWS_3/19/16).
//! - [`tf_overpermissive_iam`] — IAM policy granting `*` on `*` with Allow (CKV_AWS_1).
//! - [`tf_public_s3_bucket`] — `aws_s3_bucket` public ACL or no public-access-block (CKV_AWS_53).
//! - [`tf_no_state_encryption`] — Terraform S3 backend without `encrypt = true` (CKV_TF_1).
//! - [`k8s_run_as_root`] — pod / container missing `runAsNonRoot: true` (kube-linter).
//! - [`k8s_latest_tag`] — container image pinned to `:latest` or implicit-latest (kube-linter).
//! - [`k8s_writable_root_fs`] — container missing `readOnlyRootFilesystem: true` (kube-linter).
//! - [`k8s_privileged`] — container `privileged: true` (kube-linter privileged-container).
//! - [`k8s_host_network`] — pod spec `hostNetwork: true` (kube-linter host-network).
//!
//! See [`BuiltinIacPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cloudformation_no_drift_detection;
pub mod compose_default_network;
pub mod dockerfile_apt_no_clean;
pub mod dockerfile_latest_tag;
pub mod dockerfile_no_user;
pub mod helm_no_chart_lock;
mod helpers;
pub mod k8s_host_network;
pub mod k8s_latest_tag;
pub mod k8s_no_resource_limits;
pub mod k8s_no_security_context;
pub mod k8s_privileged;
pub mod k8s_run_as_root;
pub mod k8s_writable_root_fs;
mod pack;
pub mod terraform_no_lifecycle_protection;
pub mod tf_no_state_encryption;
pub mod tf_overpermissive_iam;
pub mod tf_public_s3_bucket;
pub mod tf_unencrypted_storage;
pub mod tf_unrestricted_ssh;
pub mod workflow_inline_secret;

#[cfg(test)]
mod tests;

pub use pack::BuiltinIacPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinIacPack::PACK_ID;
