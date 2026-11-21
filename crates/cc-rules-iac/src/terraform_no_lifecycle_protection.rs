//! `cc.iac.terraform_no_lifecycle_protection` — high-risk TF resource without
//! `lifecycle { prevent_destroy = true }`.
//!
//! Heuristic: scan `*.tf` files for `resource "<type>" "<name>"` blocks
//! whose type is in `TF_HIGH_RISK_RESOURCES`. A `terraform apply` that
//! recreates one of these (because of an attribute change in a previous
//! resource) silently destroys data — production RDS, DynamoDB tables,
//! S3 buckets. `prevent_destroy = true` makes Terraform refuse the
//! destroy step instead of paving the row.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_iac_test_fixture, is_terraform_path, location_for_file, IacFindingBlueprint,
    TF_HIGH_RISK_RESOURCES,
};

/// Family-29 probe R-IAC-TERRAFORM-NO-LIFECYCLE.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerraformNoLifecycleProtectionRule;

impl Rule for TerraformNoLifecycleProtectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.terraform_no_lifecycle_protection"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "Terraform high-risk resource without `lifecycle.prevent_destroy = true`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_terraform_path(&path) || is_iac_test_fixture(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            scan_blocks(text, &path, &mut out);
        }
        out
    }
}

/// Walk `text`, find each `resource "<type>" "<name>" { … }` block,
/// and check whether the matching type is high-risk + missing protection.
fn scan_blocks(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let mut state = BlockScanState::default();
    for (idx, line) in text.lines().enumerate() {
        let lineno = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if let Some(hit) = process_block_line(line, lineno, &mut state) {
            out.push(emit(path, hit.start_line, hit.resource_type));
        }
    }
}

/// In-flight scanner state for a single Terraform file. One state value
/// is mutated as the line iterator advances.
#[derive(Debug, Default)]
pub(crate) struct BlockScanState {
    depth: i32,
    block_start_line: u32,
    current_type: Option<&'static str>,
    current_body: String,
}

/// One block hit ready to be emitted as a finding.
#[derive(Debug)]
struct BlockHit {
    start_line: u32,
    resource_type: &'static str,
}

/// Advance `state` by one Terraform source line. Returns a [`BlockHit`]
/// when this line closes a high-risk resource block that lacks a
/// `prevent_destroy` lifecycle stanza.
fn process_block_line(line: &str, lineno: u32, state: &mut BlockScanState) -> Option<BlockHit> {
    capture_block_header(line, lineno, state);
    accumulate_body(line, state);
    update_brace_depth(line, state);
    finalize_block_if_closed(state)
}

/// When we are at top-level (`depth == 0`), record the start of a new
/// high-risk resource block.
fn capture_block_header(line: &str, lineno: u32, state: &mut BlockScanState) {
    if state.depth != 0 {
        return;
    }
    let Some(rt) = parse_resource_header(line) else {
        return;
    };
    state.current_type = Some(rt);
    state.current_body.clear();
    state.block_start_line = lineno;
}

/// Append `line` to the in-flight body buffer when we are inside a
/// tracked block.
fn accumulate_body(line: &str, state: &mut BlockScanState) {
    if state.current_type.is_none() {
        return;
    }
    state.current_body.push_str(line);
    state.current_body.push('\n');
}

/// Update the running `{` / `}` depth from one source line.
fn update_brace_depth(line: &str, state: &mut BlockScanState) {
    state.depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
    state.depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
}

/// When the in-flight block has closed, decide whether to emit a hit
/// and reset the state for the next block.
fn finalize_block_if_closed(state: &mut BlockScanState) -> Option<BlockHit> {
    if state.depth > 0 || state.current_type.is_none() {
        return None;
    }
    let resource_type = state.current_type.take()?;
    let hit = (!has_prevent_destroy(&state.current_body)).then_some(BlockHit {
        start_line: state.block_start_line,
        resource_type,
    });
    state.depth = 0;
    state.current_body.clear();
    hit
}

/// Return the high-risk resource type when `line` opens a matching
/// `resource "<type>" "<name>" {` block; `None` otherwise.
fn parse_resource_header(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("resource ") {
        return None;
    }
    let after = trimmed["resource ".len()..].trim_start();
    let rest = after.strip_prefix('"')?;
    let (type_name, _) = rest.split_once('"')?;
    TF_HIGH_RISK_RESOURCES
        .iter()
        .copied()
        .find(|rt| *rt == type_name)
}

pub(crate) fn has_prevent_destroy(body: &str) -> bool {
    let normalized: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.contains("prevent_destroy = true") || normalized.contains("prevent_destroy=true")
}

fn emit(path: &Utf8PathBuf, lineno: u32, resource_type: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.terraform_no_lifecycle_protection",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!(
            "Terraform `{resource_type}` at `{}:{lineno}` has no `prevent_destroy`",
            path.as_str()
        ),
        explanation: format!(
            "Resource `{resource_type}` declared at `{}:{lineno}` has \
             no `lifecycle {{ prevent_destroy = true }}`. A future \
             attribute change Terraform considers force-new (encryption \
             setting, name, certain tags) will plan a destroy + create, \
             silently obliterating production data on the next `apply`.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Inside the resource block, add:\n  lifecycle {\n    \
             prevent_destroy = true\n    ignore_changes = [tags]\n  }\n\
             Pair with state-locking (`terraform_remote_state` + DynamoDB \
             lock table) and a manual review gate on plans that touch \
             stateful resources."
                .into(),
        ),
        snippet: format!("resource \"{resource_type}\" {{ … }}"),
        weight: 5,
    })
}
