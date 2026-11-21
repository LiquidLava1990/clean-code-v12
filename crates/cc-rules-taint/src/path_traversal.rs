//! `cc.taint.path_traversal` — tainted value reaches a filesystem path
//! API without normalization.
//!
//! Sink table:
//!
//! - **Python**: `open`, `os.path.join`, `pathlib.Path`, `io.open`.
//! - **Rust**: `Path::new`, `PathBuf::from`, `std::fs::File::open`.
//! - **Node**: `fs.readFile`, `fs.writeFile`, `fs.createReadStream`.
//! - **Go**: `os.Open`, `os.OpenFile`, `os.ReadFile`, `ioutil.ReadFile`.
//!
//! Sanitizers are the canonical normalize / canonicalize calls
//! (`os.path.normpath`, `os.path.realpath`, `Path::canonicalize`,
//! `path.resolve`, `realpath`). When one fires inside the same Function
//! the relevant identifier names leave the tainted set.
//!
//! # Source-context awareness
//!
//! Path traversal is a *web* attack: an attacker over the network
//! supplies `..` segments to escape the intended directory. CLI tools
//! reading the file the user explicitly named on argv are exhibiting
//! the *feature*, not a vulnerability. This rule therefore consumes
//! [`SOURCES_WEB`] only — `os.Args`, `std::env::args`, `process.argv`
//! and friends are deliberately excluded.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, TaintRuleSpec, SOURCES_WEB};

const SINKS: &[&str] = &[
    "open",
    "io.open",
    "os.path.join",
    "pathlib.Path",
    "Path",
    "Path::new",
    "PathBuf::from",
    "std::fs::File::open",
    "std::fs::read",
    "std::fs::read_to_string",
    "std::fs::write",
    "fs.readFile",
    "fs.readFileSync",
    "fs.writeFile",
    "fs.writeFileSync",
    "fs.createReadStream",
    "os.Open",
    "os.OpenFile",
    "os.ReadFile",
    "ioutil.ReadFile",
];

/// Family-4 probe `cc.taint.path_traversal`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PathTraversalRule;

impl Rule for PathTraversalRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.path_traversal"
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
        "tainted value reaches a filesystem path API without normalization"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.path_traversal",
                sources: SOURCES_WEB,
                sinks: SINKS,
                confidence: 0.98,
                weight: 7,
                message: build_message,
                remediation: "Canonicalize the path with \
                              `os.path.realpath` / `Path::canonicalize` \
                              / `path.resolve` and assert it sits \
                              under an allow-listed root before opening. \
                              Reject any input containing `..`.",
                sink_arg_check: None,
                // Disable parameter seeding: every developer-CLI helper
                // takes a `&Path` parameter and that is the *feature*,
                // not a path-traversal vulnerability. Real flows must
                // come from an explicit web source-call (request.GET,
                // axum extractor, etc.) which we still detect.
                seed_parameters: false,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted input reaches filesystem sink `{callee}` without normalization");
    let body = format!(
        "A request- or env-derived value flows into `{callee}` with no \
         intervening canonicalization. An attacker can use `..` segments \
         to escape the intended directory and read or write arbitrary \
         files (path traversal)."
    );
    (head, body)
}
