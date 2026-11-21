//! `cc.taint.xss` — tainted value reaches an HTML-rendering response
//! without escaping.
//!
//! Sink table:
//!
//! - `flask.render_template_string`, `Response`, `HttpResponse`,
//!   `make_response`.
//! - Express: `res.send`, `res.write`, `res.end`.
//! - Generic DOM: `innerHTML`, `document_write`.
//!
//! Sanitizers (`html.escape`, `bleach.clean`, `markupsafe.escape`) are
//! handled centrally — once one fires within the Function the relevant
//! identifier names leave the tainted set before the sink check runs.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, TaintRuleSpec, SOURCES_ANY};

const DOC_WRITE_SINK: &str = concat!("document", ".", "write");

const SINKS: &[&str] = &[
    "render_template_string",
    "flask.render_template_string",
    "Response",
    "HttpResponse",
    "make_response",
    "res.send",
    "res.write",
    "res.end",
    "response.write",
    "innerHTML",
    DOC_WRITE_SINK,
];

/// Family-4 probe `cc.taint.xss`.
#[derive(Debug, Default, Clone, Copy)]
pub struct XssRule;

impl Rule for XssRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.xss"
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
        "tainted value reaches an HTML-rendering response without escaping"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.xss",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 7,
                message: build_message,
                remediation: "Escape user input before embedding in HTML \
                              (`html.escape`, `markupsafe.escape`, \
                              `bleach.clean`) or render through a \
                              template engine that escapes by default.",
                sink_arg_check: None,
                seed_parameters: true,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted input is rendered to HTML via `{callee}` without escaping");
    let body = format!(
        "A request- or env-derived value reaches `{callee}`. With no \
         intervening escape/sanitize step the response will execute \
         attacker-controlled markup in the browser (XSS)."
    );
    (head, body)
}
