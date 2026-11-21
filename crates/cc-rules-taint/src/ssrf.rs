//! `cc.taint.ssrf` — tainted value is used as the URL of an outbound
//! HTTP request.
//!
//! Sink table:
//!
//! - **Python**: `requests.get`, `requests.post`, `requests.request`,
//!   `urllib.request.urlopen`, `httpx.get`, `aiohttp.ClientSession.get`.
//! - **Node**: `axios.get`, `axios.post`, `fetch`, `http.get`,
//!   `https.get`.
//! - **Rust**: `reqwest::get`, `reqwest::Client::get`,
//!   `ureq::get`.
//! - **Go**: `http.Get`, `http.Post`, `http.NewRequest`.
//!
//! Parameter-seeding is OFF for this rule. Utility / library /
//! scraper code routinely takes `url: str` as a function parameter and
//! passes it straight to `requests.get` — that pattern is the *purpose*
//! of a fetch helper, not a vulnerability. Without parameter seeding
//! the rule still fires on the canonical SSRF flow `request.json["url"]
//! → requests.get(url)`, which is the genuine attacker-controlled
//! shape, while the false positives on internal helpers (whose `url`
//! comes from the caller, not from the network) drop out.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, TaintRuleSpec, SOURCES_ANY};

const SINKS: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.urlopen",
    "httpx.get",
    "httpx.post",
    "aiohttp.ClientSession.get",
    "axios.get",
    "axios.post",
    "axios.request",
    "fetch",
    "http.get",
    "https.get",
    "http.request",
    "https.request",
    "reqwest::get",
    "reqwest::Client::get",
    "Client::get",
    "ureq::get",
    "http.Get",
    "http.Post",
    "http.NewRequest",
];

/// Family-4 probe `cc.taint.ssrf`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SsrfRule;

impl Rule for SsrfRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.ssrf"
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
        "tainted value used as outbound HTTP URL (server-side request forgery)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.ssrf",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 8,
                message: build_message,
                remediation: "Validate the URL against an allow-list of \
                              schemes + hosts before requesting. Block \
                              private IP ranges (10.x, 172.16.x, \
                              192.168.x, 169.254.x, 127.x, ::1) — the \
                              standard SSRF deny-list.",
                sink_arg_check: None,
                seed_parameters: false,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted URL flows into outbound request `{callee}` (SSRF risk)");
    let body = format!(
        "A request- or env-derived value reaches `{callee}` as the URL \
         argument. Without an allow-list the attacker can reach internal \
         services (cloud metadata, RFC1918 ranges, localhost) — the \
         classic SSRF pivot."
    );
    (head, body)
}
