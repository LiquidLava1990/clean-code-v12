//! `cc.error.swallowed_with_log` — `except: log.error(...); pass` /
//! `try { ... } catch { console.log(...) }` patterns.
//!
//! Severity: BLOCKER. Swallowing an exception with only a log line is
//! the canonical "production silently broken" bug — the system reports
//! green but the user-facing operation never happened.

use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.error.swallowed_with_log`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SwallowedWithLogRule;

impl Rule for SwallowedWithLogRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.swallowed_with_log"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "exception swallowed with only a log line"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = enclosing_file_path(ctx.batch, file.id) else {
                continue;
            };
            let bytes = ctx.source.get(&path);
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for snippet in find_swallowed_blocks(text) {
                let location = location_from_node(ctx.batch, file.id, path.clone());
                out.push(build_finding(CompletenessFindingBlueprint {
                    rule_id: "cc.error.swallowed_with_log",
                    category: Category::Bug,
                    severity: Severity::Blocker,
                    confidence: Confidence::new(0.85),
                    location,
                    headline: "exception swallowed — only logged".to_owned(),
                    explanation: "Catching an exception, logging it, and continuing on \
                         hides production breakage. The caller thinks the operation \
                         succeeded but the side effect never landed."
                        .into(),
                    remediation: Remediation::SuggestedRewrite(
                        "Either re-raise (`raise from`) or convert the failure to a \
                         typed Result the caller is forced to handle."
                            .into(),
                    ),
                    snippet,
                    weight: 3,
                }));
            }
        }
        out
    }
}

/// Look for the swallow-then-log idiom across multiple syntaxes.
fn find_swallowed_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !is_catch_line(line) {
            continue;
        }
        let next = lines.get(i + 1).copied().unwrap_or("");
        let after = lines.get(i + 2).copied().unwrap_or("");
        if is_log_only_followup(next, after) {
            out.push(format!("{}\n{}", line.trim(), next.trim()));
        }
    }
    out
}

fn is_catch_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("except")
        || trimmed.starts_with("} catch")
        || trimmed.starts_with("catch (")
}

fn is_log_only_followup(next: &str, after: &str) -> bool {
    let next_trim = next.trim_start();
    let after_trim = after.trim_start();
    let logs = next_trim.starts_with("log")
        || next_trim.starts_with("logger")
        || next_trim.starts_with("console.")
        || next_trim.starts_with("tracing::");
    if !logs {
        return false;
    }
    let recovers = after_trim.starts_with("raise")
        || after_trim.starts_with("throw")
        || after_trim.starts_with("return Err")
        || after_trim.starts_with("return new Err");
    !recovers
}
