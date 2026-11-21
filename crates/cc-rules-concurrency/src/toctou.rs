//! `cc.concurrent.toctou` — check-then-use across a syscall boundary.
//!
//! Heuristic: inside a single function body, find a Call that matches
//! `os.path.exists(p)` / `Path::exists(&p)` / `fs.existsSync(p)`
//! followed by a Call to `open(p)` / `fs.readFile(p)` / `File::open(p)`
//! with the SAME path argument. The window between the two calls is a
//! TOCTOU race: another process can swap or delete `p`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, collect_descendant_calls, enclosing_file_path, first_arg_text,
    location_from_node, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONCURRENT-TOCTOU.
#[derive(Debug, Default, Clone, Copy)]
pub struct ToctouRule;

const CHECK_CALLEES: &[&str] = &[
    "os.path.exists",
    "os.path.isfile",
    "os.path.isdir",
    "Path::exists",
    "fs.existsSync",
    "fs.exists",
    "Stat",
    "os.Stat",
];

const USE_CALLEES: &[&str] = &[
    "open",
    "io.open",
    "fs.readFile",
    "fs.readFileSync",
    "fs.writeFile",
    "fs.writeFileSync",
    "File::open",
    "File::create",
    "os.Open",
    "ioutil.ReadFile",
    "std::fs::read",
    "std::fs::write",
];

impl Rule for ToctouRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.toctou"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "check-then-use file pattern (TOCTOU race)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for fun in nodes_of_kind(ctx.batch, kind) {
                scan_function(ctx, fun.id, &mut out);
            }
        }
        out
    }
}

fn scan_function(ctx: &RuleContext<'_>, fun: NodeId, out: &mut Vec<Finding>) {
    let mut calls: Vec<NodeId> = Vec::new();
    collect_descendant_calls(ctx.batch, fun, &mut calls);
    let checks: Vec<(usize, NodeId, String)> = calls
        .iter()
        .enumerate()
        .filter_map(|(i, c)| build_call_record(ctx, *c, i, CHECK_CALLEES))
        .collect();
    if checks.is_empty() {
        return;
    }
    let uses: Vec<(usize, NodeId, String)> = calls
        .iter()
        .enumerate()
        .filter_map(|(i, c)| build_call_record(ctx, *c, i, USE_CALLEES))
        .collect();
    for (check_pos, check_id, path_arg) in &checks {
        if let Some(use_id) = find_matching_use(&uses, *check_pos, path_arg) {
            if let Some(finding) = emit(ctx, *check_id, use_id, path_arg) {
                out.push(finding);
            }
        }
    }
}

fn build_call_record(
    ctx: &RuleContext<'_>,
    call: NodeId,
    idx: usize,
    table: &[&str],
) -> Option<(usize, NodeId, String)> {
    let text = callee_text(ctx.batch, call);
    if !table.iter().any(|n| text.contains(n)) {
        return None;
    }
    let arg = first_arg_text(ctx.batch, call)?;
    Some((idx, call, arg))
}

fn find_matching_use(
    uses: &[(usize, NodeId, String)],
    check_pos: usize,
    path_arg: &str,
) -> Option<NodeId> {
    uses.iter()
        .find(|(pos, _, arg)| *pos > check_pos && arg == path_arg)
        .map(|(_, id, _)| *id)
}

fn emit(
    ctx: &RuleContext<'_>,
    check: NodeId,
    _use_call: NodeId,
    path_arg: &str,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, check)?;
    let location = location_from_node(ctx.batch, check, path);
    Some(build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.toctou",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("TOCTOU: existence check then open of `{path_arg}`"),
        explanation: format!(
            "The path `{path_arg}` is checked for existence and then opened \
             in the same function. Another process can swap, delete, or \
             symlink the path between the two calls — the check buys \
             nothing and a malicious actor can use the gap for privilege \
             escalation."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Skip the check and handle the open's error directly \
             (`FileNotFoundError`, `ENOENT`). On Linux, prefer `O_NOFOLLOW` \
             / `openat` with a directory fd that you already opened \
             securely."
                .into(),
        ),
        snippet: path_arg.to_owned(),
        weight: 4,
    }))
}
