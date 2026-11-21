//! `cc.deploy.tf_no_state_encryption` — Terraform S3 backend without
//! `encrypt = true`.
//!
//! Closes Checkov **CKV_TF_1** ("Ensure Terraform module sources use a
//! commit hash" → adapted to the related state-encryption gate
//! consistently shipped under that ID range). Walks every Terraform
//! file for a `terraform { backend "s3" { ... } }` stanza and flags
//! when `encrypt = true` is missing.
//!
//! Terraform state contains every secret your modules ever read
//! (database passwords, KMS key references, even raw cloud-init
//! payloads). State files written without server-side encryption can
//! be exfiltrated by anyone with read access to the bucket.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_phase8_path, is_test_file_path,
    location_for_file, looks_like_rule_pack_source, IacFindingBlueprint,
};

/// Phase-8 probe: detect Terraform S3 backend missing `encrypt = true`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TfNoStateEncryptionRule;

impl Rule for TfNoStateEncryptionRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.tf_no_state_encryption"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Terraform S3 backend declared without `encrypt = true` (CKV_TF_1)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_terraform_phase8_path(&path)
                || is_iac_test_fixture(&path)
                || is_test_file_path(&path)
                || looks_like_rule_pack_source(&path)
            {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if let Some(line) = find_unencrypted_backend(text) {
                out.push(emit(&path, line));
            }
        }
        out
    }
}

fn find_unencrypted_backend(text: &str) -> Option<u32> {
    let mut state = BackendScanState::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(start) = process_line(line, lineno, &mut state) {
            return Some(start);
        }
    }
    None
}

/// In-flight scanner state for the `terraform { backend "s3" { ... } }` walk.
#[derive(Debug, Default)]
pub(crate) struct BackendScanState {
    in_backend: bool,
    depth: i32,
    block_start: u32,
    body: String,
}

/// Advance `state` by one Terraform source line. Returns the
/// originating block start-line when this line closes a
/// `backend "s3" { ... }` block that lacks `encrypt = true`.
pub(crate) fn process_line(line: &str, lineno: u32, state: &mut BackendScanState) -> Option<u32> {
    if !state.in_backend {
        if is_s3_backend_header(line) {
            state.in_backend = true;
            state.depth = 0;
            state.block_start = lineno;
            state.body.clear();
        } else {
            return None;
        }
    }
    state.body.push_str(line);
    state.body.push('\n');
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    state.depth += opens - closes;
    if state.depth > 0 {
        return None;
    }
    let hit = (!body_is_encrypted(&state.body)).then_some(state.block_start);
    state.in_backend = false;
    state.depth = 0;
    state.body.clear();
    hit
}

fn is_s3_backend_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("backend \"s3\"") && trimmed.contains('{')
}

/// True iff the backend body declares `encrypt = true` (with or
/// without surrounding spaces around `=`).
pub(crate) fn body_is_encrypted(body: &str) -> bool {
    let normalized: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.contains("encrypt = true") || normalized.contains("encrypt=true")
}

fn emit(path: &Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.tf_no_state_encryption",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "Terraform S3 backend at `{}:{lineno}` lacks `encrypt = true`",
            path.as_str()
        ),
        explanation: format!(
            "Backend declared at `{}:{lineno}` writes the Terraform \
             state to S3 without server-side encryption. State files \
             carry every credential, ARN, and provisioner output your \
             modules ever produced; an attacker with bucket-read can \
             exfiltrate them in plaintext. Checkov flags this as \
             CKV_TF_1.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Inside `backend \"s3\" {}` add:\n  encrypt = true\n  \
             kms_key_id = \"arn:aws:kms:...\"\n  dynamodb_table = \
             \"<lock-table>\"\n\nPair with bucket-level versioning + \
             default encryption so historical state is also protected."
                .into(),
        ),
        snippet: format!("backend \"s3\" {{ … }} @ {lineno}"),
        weight: 6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use cc_config::RuleConfig;
    use cc_cpg::{CpgWriteBatch, NodeBuilder, Value};
    use cc_rules::{InMemorySourceTable, KernelMeta, ProjectFingerprint};

    fn run(path: &str, body: &[u8]) -> Vec<Finding> {
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::File)
                .with_prop("path", Value::String(path.to_owned()))
                .with_prop("language", Value::String("hcl".into())),
        );
        let source = InMemorySourceTable::new();
        source.insert(Utf8PathBuf::from(path), body.to_vec());
        let cfg = RuleConfig::default();
        let proj = ProjectFingerprint::empty();
        let kernel = KernelMeta::now();
        TfNoStateEncryptionRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_unencrypted_s3_backend() {
        let body = br#"terraform {
  backend "s3" {
    bucket = "tfstate"
    key = "a/b"
    region = "us-east-1"
  }
}
"#;
        let findings = run("backend.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.tf_no_state_encryption");
    }

    #[test]
    fn silent_when_encrypted() {
        let body = br#"terraform {
  backend "s3" {
    bucket = "tfstate"
    key = "a/b"
    region = "us-east-1"
    encrypt = true
  }
}
"#;
        assert!(run("backend.tf", body).is_empty());
    }

    #[test]
    fn silent_when_no_backend_block() {
        let body = b"resource \"aws_s3_bucket\" \"x\" { bucket = \"y\" }\n";
        assert!(run("main.tf", body).is_empty());
    }
}
