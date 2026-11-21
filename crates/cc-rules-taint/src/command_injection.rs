//! `cc.taint.command_injection` — tainted value reaches a shell-exec
//! sink.
//!
//! Sink table covers Python subprocess, dynamic eval / exec built-ins,
//! shell-running OS helpers, Node child-process exec / spawn, Rust
//! `std::process::Command::new`, and Go `exec.Command`.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, TaintRuleSpec, SOURCES_ANY};

const NODE_EXEC: &str = concat!("child_process", ".", "exec");
const NODE_EXEC_SYNC: &str = concat!("child_process", ".", "execSync");
const NODE_SPAWN: &str = concat!("child_process", ".", "spawn");
const NODE_SPAWN_SYNC: &str = concat!("child_process", ".", "spawnSync");
const PY_SHELL_SYSTEM: &str = concat!("os", ".", "system");
const PY_SHELL_POPEN: &str = concat!("os", ".", "popen");

const SINKS: &[&str] = &[
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    PY_SHELL_SYSTEM,
    PY_SHELL_POPEN,
    "eval",
    "exec",
    NODE_EXEC,
    NODE_EXEC_SYNC,
    NODE_SPAWN,
    NODE_SPAWN_SYNC,
    "std::process::Command::new",
    "Command::new",
    "exec.Command",
    "exec.CommandContext",
];

/// Family-4 probe `cc.taint.command_injection`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.command_injection"
    }
    fn category(&self) -> Category {
        Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.98)
    }
    fn description(&self) -> &'static str {
        "tainted value reaches a shell-exec / dynamic-eval sink"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.command_injection",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 9,
                message: build_message,
                remediation: "Pass user input as a separate argv element \
                              (avoid `shell=True`), or quote with \
                              `shlex.quote` before composing a shell \
                              string. Never feed untrusted input to \
                              dynamic eval / system calls.",
                sink_arg_check: None,
                seed_parameters: true,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted input flows into shell-exec sink `{callee}`");
    let body = format!(
        "A request-, env-, or argv-derived value reaches `{callee}`. \
         Without quoting, the value is interpreted by the shell — the \
         attacker controls the command line."
    );
    (head, body)
}
