//! `cc.deploy.tf_overpermissive_iam` — IAM policy granting
//! `Action: "*"` AND `Resource: "*"` AND `Effect: "Allow"`.
//!
//! Closes Checkov **CKV_AWS_1** ("Ensure IAM policies that allow full
//! `*-*` admin privileges are not created"). The probe scans every
//! Terraform file for inline `aws_iam_policy_document` data blocks and
//! `aws_iam_policy` / `aws_iam_role_policy` heredoc bodies that
//! simultaneously assert the three keys.
//!
//! Detection is structural: we look for a single window of text that
//! pairs `"Effect": "Allow"`, `"Action": "*"` (or `["*"]`), and
//! `"Resource": "*"` (or `["*"]`) within a 40-line span. The window
//! survives whitespace + key-order variation.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_phase8_path, is_test_file_path,
    location_for_file, looks_like_rule_pack_source, IacFindingBlueprint,
};

/// Phase-8 probe: detect Terraform IAM policy granting `*-*-Allow`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TfOverpermissiveIamRule;

impl Rule for TfOverpermissiveIamRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.tf_overpermissive_iam"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Terraform IAM policy grants Action=* on Resource=* with Allow (CKV_AWS_1)"
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
            scan_policies(text, &path, &mut out);
        }
        out
    }
}

fn scan_policies(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    if let Some(line) = find_violating_window(text) {
        out.push(emit(path, line));
    }
    if let Some(line) = find_hcl_data_block_violation(text) {
        out.push(emit(path, line));
    }
}

/// JSON-style scan: find a 40-line window naming Allow, *, * together.
fn find_violating_window(text: &str) -> Option<u32> {
    let lines: Vec<&str> = text.lines().collect();
    let window: usize = 40;
    for i in 0..lines.len() {
        let end = (i + window).min(lines.len());
        let chunk: String = lines[i..end].join("\n");
        if window_grants_full_admin(&chunk) {
            return Some(u32::try_from(i + 1).unwrap_or(u32::MAX));
        }
    }
    None
}

fn window_grants_full_admin(chunk: &str) -> bool {
    let normalized: String = chunk.split_whitespace().collect::<Vec<_>>().join(" ");
    let allow =
        normalized.contains("\"Effect\": \"Allow\"") || normalized.contains("\"Effect\":\"Allow\"");
    let action_star = normalized.contains("\"Action\": \"*\"")
        || normalized.contains("\"Action\":\"*\"")
        || normalized.contains("\"Action\": [\"*\"]")
        || normalized.contains("\"Action\":[\"*\"]");
    let resource_star = normalized.contains("\"Resource\": \"*\"")
        || normalized.contains("\"Resource\":\"*\"")
        || normalized.contains("\"Resource\": [\"*\"]")
        || normalized.contains("\"Resource\":[\"*\"]");
    allow && action_star && resource_star
}

/// HCL `data "aws_iam_policy_document"` block: `effect = "Allow"`,
/// `actions = ["*"]`, `resources = ["*"]`.
fn find_hcl_data_block_violation(text: &str) -> Option<u32> {
    let mut state = HclPolicyScan::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(start) = process_hcl_line(line, lineno, &mut state) {
            return Some(start);
        }
    }
    None
}

/// In-flight scanner state for an `aws_iam_policy_document` data block.
#[derive(Debug, Default)]
pub(crate) struct HclPolicyScan {
    in_data: bool,
    depth: i32,
    block_start: u32,
    body: String,
}

/// Advance `state` by one Terraform source line. Returns the
/// originating block start-line when this line closes an
/// `aws_iam_policy_document` data block that grants `*` on `*` with
/// effect Allow.
pub(crate) fn process_hcl_line(line: &str, lineno: u32, state: &mut HclPolicyScan) -> Option<u32> {
    if !state.in_data {
        if line.contains("\"aws_iam_policy_document\"") && line.contains("data ") {
            state.in_data = true;
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
    let hit = hcl_grants_full_admin(&state.body).then_some(state.block_start);
    state.in_data = false;
    state.body.clear();
    state.depth = 0;
    hit
}

/// Returns `true` when an `aws_iam_policy_document` body is missing an
/// explicit deny effect AND opens both `actions` and `resources` to
/// `["*"]` — the canonical "full admin" shape.
pub(crate) fn hcl_grants_full_admin(body: &str) -> bool {
    let normalized: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let allow = normalized.contains("effect = \"Allow\"") || !normalized.contains("effect =");
    let actions_star =
        normalized.contains("actions = [\"*\"]") || normalized.contains("actions=[\"*\"]");
    let resources_star =
        normalized.contains("resources = [\"*\"]") || normalized.contains("resources=[\"*\"]");
    allow && actions_star && resources_star
}

fn emit(path: &Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.tf_overpermissive_iam",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "Terraform IAM policy at `{}:{lineno}` grants `*` on `*` with Allow",
            path.as_str()
        ),
        explanation: format!(
            "An IAM policy at `{}:{lineno}` grants every action on every \
             resource. Any principal binding this policy can read every \
             secret, delete every bucket, and assume every role. Checkov \
             flags this as CKV_AWS_1.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the wildcard with the minimum action + resource ARN \
             set the workload actually needs. Generate the smallest \
             policy via IAM Access Analyzer's policy-generation feature; \
             never hand-author `Action: *`."
                .into(),
        ),
        snippet: format!("Effect=Allow Action=* Resource=* @ {lineno}"),
        weight: 8,
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
        TfOverpermissiveIamRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_full_admin_json_policy() {
        let body = br#"resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  })
}
"#;
        let findings = run("iam.tf", body);
        assert!(!findings.is_empty(), "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.tf_overpermissive_iam");
    }

    #[test]
    fn silent_when_action_scoped() {
        let body = br#"resource "aws_iam_policy" "ro" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket/*"
    }]
  })
}
"#;
        assert!(run("iam.tf", body).is_empty());
    }

    #[test]
    fn flags_hcl_policy_document() {
        let body = br#"data "aws_iam_policy_document" "admin" {
  statement {
    effect = "Allow"
    actions = ["*"]
    resources = ["*"]
  }
}
"#;
        let findings = run("iam.tf", body);
        assert!(!findings.is_empty(), "got {findings:?}");
    }
}
