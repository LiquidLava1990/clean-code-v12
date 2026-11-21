//! `cc.deploy.tf_unencrypted_storage` — Terraform storage resource without
//! encryption-at-rest.
//!
//! Closes Checkov **CKV_AWS_3** (EBS volume encryption), **CKV_AWS_19**
//! (S3 bucket encryption), and **CKV_AWS_16** (RDS encryption). Walks
//! every Terraform file, isolates each `resource "<type>" "<name>"`
//! block, and flags blocks where:
//!
//! - `aws_ebs_volume`  : `encrypted = true` is missing OR set to `false`.
//! - `aws_db_instance` : `storage_encrypted = true` is missing OR `false`.
//! - `aws_s3_bucket`   : neither `server_side_encryption_configuration`
//!                       sub-block nor `aws_s3_bucket_server_side_encryption_configuration`
//!                       sibling resource is present in the file.
//!
//! Heuristic — single-pass brace walker, follows the same shape as
//! [`crate::terraform_no_lifecycle_protection`].

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_phase8_path, is_test_file_path,
    location_for_file, looks_like_rule_pack_source, IacFindingBlueprint,
};

/// Phase-8 probe: detect Terraform storage resources missing encryption.
#[derive(Debug, Default, Clone, Copy)]
pub struct TfUnencryptedStorageRule;

const TARGET_RESOURCES: &[&str] = &["aws_ebs_volume", "aws_s3_bucket", "aws_db_instance"];

impl Rule for TfUnencryptedStorageRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.tf_unencrypted_storage"
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
        "Terraform storage resource missing encryption-at-rest (CKV_AWS_3/19/16)"
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
            scan(text, &path, &mut out);
        }
        out
    }
}

fn scan(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let has_sibling_sse = text.contains("aws_s3_bucket_server_side_encryption_configuration");
    let mut state = StorageScanState::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(hit) = process_line(line, lineno, &mut state) {
            if hit.is_violation(has_sibling_sse) {
                out.push(emit(path, hit.line, hit.resource_type));
            }
        }
    }
}

/// In-flight scanner state for a Terraform storage-resource walker.
#[derive(Debug, Default)]
pub(crate) struct StorageScanState {
    depth: i32,
    block_start: u32,
    current: Option<&'static str>,
    body: String,
}

/// One closed storage block ready for encryption classification.
#[derive(Debug)]
pub(crate) struct StorageHit {
    line: u32,
    resource_type: &'static str,
    body: String,
}

impl StorageHit {
    /// Returns `true` when the storage block lacks the encryption
    /// attribute appropriate for its resource type. The body is
    /// whitespace-normalised once and checked with literal substring
    /// matches against the canonical attribute pair.
    pub(crate) fn is_violation(&self, has_sibling_sse: bool) -> bool {
        let normalized: String = self.body.split_whitespace().collect::<Vec<_>>().join(" ");
        let attr_pair = match self.resource_type {
            "aws_ebs_volume" => ("encrypted = true", "encrypted=true"),
            "aws_db_instance" => ("storage_encrypted = true", "storage_encrypted=true"),
            "aws_s3_bucket" => {
                let inline = normalized.contains("server_side_encryption_configuration");
                return !(inline || has_sibling_sse);
            }
            _ => return false,
        };
        let (spaced, tight) = attr_pair;
        !(normalized.contains(spaced) || normalized.contains(tight))
    }
}

/// Advance `state` by one Terraform source line. Returns a closed
/// [`StorageHit`] when this line closes one of the tracked storage
/// resources, ready for encryption-violation classification.
pub(crate) fn process_line(
    line: &str,
    lineno: u32,
    state: &mut StorageScanState,
) -> Option<StorageHit> {
    if state.depth == 0 && state.current.is_none() {
        if let Some(rt) = parse_resource_header(line) {
            state.current = Some(rt);
            state.block_start = lineno;
            state.body.clear();
        }
    }
    if state.current.is_some() {
        state.body.push_str(line);
        state.body.push('\n');
    }
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    state.depth += opens - closes;
    if state.depth > 0 || state.current.is_none() {
        return None;
    }
    let resource_type = state.current.take()?;
    let hit = StorageHit {
        line: state.block_start,
        resource_type,
        body: std::mem::take(&mut state.body),
    };
    state.depth = 0;
    Some(hit)
}

fn parse_resource_header(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("resource ") {
        return None;
    }
    let after = trimmed["resource ".len()..].trim_start();
    let rest = after.strip_prefix('"')?;
    let (type_name, _) = rest.split_once('"')?;
    TARGET_RESOURCES.iter().copied().find(|rt| *rt == type_name)
}

fn emit(path: &Utf8PathBuf, lineno: u32, resource_type: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    let (ckv, attr) = match resource_type {
        "aws_ebs_volume" => ("CKV_AWS_3", "encrypted = true"),
        "aws_db_instance" => ("CKV_AWS_16", "storage_encrypted = true"),
        "aws_s3_bucket" => ("CKV_AWS_19", "server_side_encryption_configuration { ... }"),
        _ => ("CKV_AWS_*", "<encryption attribute>"),
    };
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.tf_unencrypted_storage",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "Terraform `{resource_type}` at `{}:{lineno}` lacks encryption-at-rest ({ckv})",
            path.as_str()
        ),
        explanation: format!(
            "Resource `{resource_type}` at `{}:{lineno}` does not declare \
             encryption. Anyone with snapshot or backup access reads \
             plaintext customer data. Checkov flags this as {ckv}.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add `{attr}` inside the resource block. Pair with a \
             customer-managed KMS key when handling regulated data."
        )),
        snippet: format!("resource \"{resource_type}\" {{ … }} @ {lineno}"),
        weight: 5,
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
        TfUnencryptedStorageRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_unencrypted_ebs() {
        let body = b"resource \"aws_ebs_volume\" \"data\" {\n  size = 100\n}\n";
        let findings = run("ebs.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.tf_unencrypted_storage");
    }

    #[test]
    fn silent_when_ebs_encrypted() {
        let body = b"resource \"aws_ebs_volume\" \"data\" {\n  size = 100\n  encrypted = true\n}\n";
        assert!(run("ebs.tf", body).is_empty());
    }

    #[test]
    fn silent_when_s3_has_sibling_sse_resource() {
        let body = br#"resource "aws_s3_bucket" "main" {
  bucket = "x"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id
}
"#;
        assert!(run("s3.tf", body).is_empty());
    }

    #[test]
    fn flags_unencrypted_rds() {
        let body = b"resource \"aws_db_instance\" \"db\" {\n  engine = \"postgres\"\n}\n";
        let findings = run("rds.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
    }
}
