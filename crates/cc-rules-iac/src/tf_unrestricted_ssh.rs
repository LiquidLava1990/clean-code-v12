//! `cc.deploy.tf_unrestricted_ssh` — security-group ingress opens SSH (port 22)
//! to the world (`0.0.0.0/0`).
//!
//! Closes Checkov **CKV_AWS_24** ("Ensure no security groups allow ingress
//! from 0.0.0.0:0 to port 22"). Walks every Terraform file, locates
//! `ingress {` blocks inside `aws_security_group` (or
//! `aws_security_group_rule`) resources, and flags any block whose
//! `from_port` covers 22 AND whose `cidr_blocks` contains `"0.0.0.0/0"`.
//!
//! Heuristic — no full HCL parser. Brace-depth tracking matches the
//! pattern used in [`crate::terraform_no_lifecycle_protection`].

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_phase8_path, is_test_file_path,
    location_for_file, looks_like_rule_pack_source, IacFindingBlueprint,
};

/// Phase-8 probe: detect Terraform SG ingress on port 22 from `0.0.0.0/0`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TfUnrestrictedSshRule;

impl Rule for TfUnrestrictedSshRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.tf_unrestricted_ssh"
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
        "Terraform security group exposes SSH (22/tcp) to 0.0.0.0/0 (CKV_AWS_24)"
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
            scan_ingress_blocks(text, &path, &mut out);
        }
        out
    }
}

/// Walk `text` and emit a finding for each ingress block whose port
/// range covers 22 AND opens 0.0.0.0/0.
fn scan_ingress_blocks(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let mut state = IngressScanState::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(start_line) = process_line(line, lineno, &mut state) {
            out.push(emit(path, start_line));
        }
    }
}

/// In-flight scanner state for one Terraform `ingress` block.
#[derive(Debug, Default)]
pub(crate) struct IngressScanState {
    depth: i32,
    in_ingress: bool,
    block_start: u32,
    body: String,
}

/// Advance `state` by one Terraform source line. Returns the
/// originating block start-line when this line closes an `ingress`
/// block whose body opens port 22 to `0.0.0.0/0`.
pub(crate) fn process_line(line: &str, lineno: u32, state: &mut IngressScanState) -> Option<u32> {
    if !state.in_ingress {
        if is_ingress_header(line) {
            state.in_ingress = true;
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
    let hit = ingress_violates(&state.body).then_some(state.block_start);
    state.in_ingress = false;
    state.body.clear();
    state.depth = 0;
    hit
}

fn is_ingress_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("ingress ") || trimmed == "ingress") && trimmed.contains('{')
}

/// Returns `true` when the block body opens port 22 to `0.0.0.0/0`.
pub(crate) fn ingress_violates(body: &str) -> bool {
    let normalized: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let opens_world = normalized.contains("\"0.0.0.0/0\"");
    if !opens_world {
        return false;
    }
    let from_port = extract_int(&normalized, "from_port");
    let to_port = extract_int(&normalized, "to_port");
    let covers_22 = match (from_port, to_port) {
        (Some(f), Some(t)) => f <= 22 && t >= 22,
        (Some(f), None) => f == 22,
        _ => false,
    };
    if covers_22 {
        return true;
    }
    // Some blocks declare `protocol = "-1"` (all) which implicitly covers 22.
    normalized.contains("protocol = \"-1\"") && opens_world
}

fn extract_int(normalized: &str, key: &str) -> Option<i64> {
    let needle = format!("{key} = ");
    let idx = normalized.find(&needle)?;
    let rest = &normalized[idx + needle.len()..];
    let token: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    token.parse().ok()
}

fn emit(path: &Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.deploy.tf_unrestricted_ssh",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "Terraform `{}:{lineno}` exposes SSH (22/tcp) to 0.0.0.0/0",
            path.as_str()
        ),
        explanation: format!(
            "Security-group ingress at `{}:{lineno}` accepts SSH from \
             every IPv4 address. Anyone on the internet can attempt \
             credential-stuffing or zero-day exploits against the \
             instance's sshd. Checkov flags this as CKV_AWS_24.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Restrict `cidr_blocks` to your bastion host or VPN CIDR \
             (e.g. `[\"10.0.0.0/16\"]`), or replace the SSH port with \
             AWS Systems Manager Session Manager so no inbound port \
             is required."
                .into(),
        ),
        snippet: format!("ingress {{ from_port = 22 cidr_blocks = [\"0.0.0.0/0\"] }} @ {lineno}"),
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

    fn fx(path: &str, body: &[u8]) -> (CpgWriteBatch, InMemorySourceTable) {
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::File)
                .with_prop("path", Value::String(path.to_owned()))
                .with_prop("language", Value::String("hcl".into())),
        );
        let source = InMemorySourceTable::new();
        source.insert(Utf8PathBuf::from(path), body.to_vec());
        (batch, source)
    }

    fn run(path: &str, body: &[u8]) -> Vec<Finding> {
        let (batch, source) = fx(path, body);
        let cfg = RuleConfig::default();
        let proj = ProjectFingerprint::empty();
        let kernel = KernelMeta::now();
        TfUnrestrictedSshRule.run(&cc_rules::RuleContext {
            batch: &batch,
            source: &source,
            config: &cfg,
            project: &proj,
            kernel: &kernel,
        })
    }

    #[test]
    fn flags_open_ssh() {
        let body = br#"resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let findings = run("sg.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].rule_id, "cc.deploy.tf_unrestricted_ssh");
    }

    #[test]
    fn silent_when_cidr_restricted() {
        let body = br#"resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"#;
        assert!(run("sg.tf", body).is_empty());
    }

    #[test]
    fn flags_all_protocols_open_world() {
        // protocol = "-1" implicitly covers port 22
        let body = br#"resource "aws_security_group" "web" {
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let findings = run("sg.tf", body);
        assert_eq!(findings.len(), 1, "got {findings:?}");
    }
}
