//! `cc.deploy.tf_public_s3_bucket` — `aws_s3_bucket` with public ACL OR
//! no `aws_s3_bucket_public_access_block` companion resource.
//!
//! Closes Checkov **CKV_AWS_53** ("Ensure S3 bucket has block public ACLs
//! enabled"). The probe scans every Terraform file for
//! `aws_s3_bucket` blocks and flags the file when EITHER:
//!
//! - The block declares `acl = "public-read"` or
//!   `acl = "public-read-write"` (legacy ACL surface), OR
//! - No `aws_s3_bucket_public_access_block` resource exists in the same
//!   file.
//!
//! Single-pass walker over the line iterator; no full HCL parse.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_phase8_path, is_test_file_path,
    location_for_file, looks_like_rule_pack_source, IacFindingBlueprint,
};

/// Phase-8 probe: detect publicly accessible S3 buckets.
#[derive(Debug, Default, Clone, Copy)]
pub struct TfPublicS3BucketRule;

impl Rule for TfPublicS3BucketRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.tf_public_s3_bucket"
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
        "Terraform `aws_s3_bucket` is public or missing public-access-block (CKV_AWS_53)"
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
    let has_public_access_block = text.contains("aws_s3_bucket_public_access_block");
    let mut state = BucketScanState::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(hit) = process_line(line, lineno, &mut state) {
            if let Some(reason) = classify(&hit, has_public_access_block) {
                out.push(emit(path, hit.line, reason));
            }
        }
    }
}

/// In-flight scanner state for an `aws_s3_bucket` resource walker.
#[derive(Debug, Default)]
pub(crate) struct BucketScanState {
    depth: i32,
    block_start: u32,
    in_bucket: bool,
    body: String,
}

/// One closed bucket block ready for ACL classification.
#[derive(Debug)]
pub(crate) struct BucketHit {
    line: u32,
    body: String,
}

/// Advance `state` by one Terraform source line. Returns a closed
/// [`BucketHit`] when this line closes an `aws_s3_bucket` block.
pub(crate) fn process_line(
    line: &str,
    lineno: u32,
    state: &mut BucketScanState,
) -> Option<BucketHit> {
    if !state.in_bucket {
        if is_bucket_header(line) {
            state.in_bucket = true;
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
    let hit = BucketHit {
        line: state.block_start,
        body: std::mem::take(&mut state.body),
    };
    state.in_bucket = false;
    state.depth = 0;
    Some(hit)
}

fn is_bucket_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("resource \"aws_s3_bucket\" ") && trimmed.contains('{')
}

fn classify(hit: &BucketHit, has_public_access_block: bool) -> Option<&'static str> {
    let normalized: String = hit.body.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.contains("acl = \"public-read-write\"") {
        return Some("acl = \"public-read-write\"");
    }
    if normalized.contains("acl = \"public-read\"") {
        return Some("acl = \"public-read\"");
    }
    if !has_public_access_block {
        return Some("no aws_s3_bucket_public_access_block companion resource");
    }
    None
}

fn emit(path: &Utf8PathBuf, lineno: u32, reason: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.tf_public_s3_bucket",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "Terraform `aws_s3_bucket` at `{}:{lineno}` is public ({reason})",
            path.as_str()
        ),
        explanation: format!(
            "S3 bucket declared at `{}:{lineno}` is reachable by the \
             public internet ({reason}). Anonymous reads expose every \
             object; anonymous writes let attackers stage malware or \
             host phishing pages on your domain. Checkov flags this as \
             CKV_AWS_53.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Remove the `acl` attribute (default `private`) and pair the \
             bucket with an `aws_s3_bucket_public_access_block` resource \
             that sets `block_public_acls`, `block_public_policy`, \
             `ignore_public_acls`, `restrict_public_buckets` to `true`."
                .into(),
        ),
        snippet: format!("aws_s3_bucket :: {reason} @ {lineno}"),
        weight: 7,
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
        TfPublicS3BucketRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_public_read_acl() {
        let body = br#"resource "aws_s3_bucket" "main" {
  bucket = "x"
  acl = "public-read"
}
resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id
}
"#;
        let findings = run("s3.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.tf_public_s3_bucket");
    }

    #[test]
    fn flags_missing_public_access_block() {
        let body = br#"resource "aws_s3_bucket" "main" {
  bucket = "x"
}
"#;
        let findings = run("s3.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
    }

    #[test]
    fn silent_when_private_with_pab() {
        let body = br#"resource "aws_s3_bucket" "main" {
  bucket = "x"
}
resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id
  block_public_acls = true
}
"#;
        assert!(run("s3.tf", body).is_empty());
    }
}
