//! `cc.concurrent.waitgroup_add_in_goroutine` — Go `wg.Add(1)` called
//! inside a `go func()` body.
//!
//! The canonical bug: a goroutine increments a `sync.WaitGroup` from
//! within its own body, racing with the parent goroutine's `Wait()`. If
//! `Wait` runs before the spawned goroutine reaches `Add`, the counter
//! is still zero, `Wait` returns immediately, and the work is dropped.
//!
//! Idiomatic Go places `wg.Add(n)` *before* spawning. This probe is a
//! source-byte heuristic over `.go` files: scan for `go func()` blocks
//! and look for `wg.Add(` (or any `*WaitGroup` receiver `.Add(`) inside.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-WAITGROUP-ADD-IN-GOROUTINE.
#[derive(Debug, Default, Clone, Copy)]
pub struct WaitgroupAddInGoroutineRule;

const GO_FUNC_OPEN: &str = "go func";
const ADD_NEEDLE: &str = ".Add(";

impl Rule for WaitgroupAddInGoroutineRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.waitgroup_add_in_goroutine"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "WaitGroup.Add() called from inside a goroutine — races with Wait()"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
                continue;
            }
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for hit in find_add_in_goroutine(text) {
        out.push(emit(path.clone(), hit));
    }
}

#[derive(Debug)]
struct Hit {
    line_no: u32,
    snippet: String,
}

fn find_add_in_goroutine(text: &str) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    let mut depth: i32 = 0;
    let mut goroutine_depth: i32 = -1;
    for (line_idx, line) in text.lines().enumerate() {
        let opens_go = line.contains(GO_FUNC_OPEN);
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if opens_go && goroutine_depth < 0 {
            goroutine_depth = depth;
        }
        depth += opens - closes;
        if goroutine_depth >= 0 && depth <= goroutine_depth {
            goroutine_depth = -1;
        }
        if goroutine_depth >= 0 && line.contains(ADD_NEEDLE) {
            out.push(Hit {
                line_no: line_idx as u32 + 1,
                snippet: line.trim().chars().take(180).collect(),
            });
        }
    }
    out
}

fn emit(path: Utf8PathBuf, hit: Hit) -> Finding {
    let pos = Position::new(hit.line_no, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.waitgroup_add_in_goroutine",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`wg.Add(...)` called from inside a goroutine body".into(),
        explanation: "`sync.WaitGroup.Add` called from within a spawned \
             goroutine races with the parent's `Wait`: if the parent \
             reaches `Wait` before the goroutine schedules far enough to \
             increment, `Wait` returns immediately and the work is dropped. \
             Idiomatic Go places `Add(n)` *before* `go func()`."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move `wg.Add(1)` up onto the line immediately above `go func()`. \
             For variadic spawning, call `wg.Add(len(items))` once before \
             the loop. The goroutine still owns the matching `defer wg.Done()`."
                .into(),
        ),
        snippet: hit.snippet,
        weight: 5,
    })
}
