//! `cc.taint.repr_on_untrusted` — invariant R-05.
//!
//! Tainted values must never be passed through a *debug*-formatting
//! sink (`repr` / `%r` / `f"{x!r}"` / `format!("{:?}", ...)` /
//! `JSON.stringify(...)`). Debug formatters reflect the **full
//! internal shape**, which on untrusted input means the
//! secret-extraction shape an attacker chose.
//!
//! # Display vs Debug
//!
//! Display-format calls (`format!("{}", x)`, `println!("user={}", x)`,
//! `tracing::info!("got {}", x)`) are SAFE — they invoke the value's
//! `Display` impl, which returns a controlled string representation.
//! Only the debug placeholders leak structure.
//!
//! The rule therefore splits its sinks into two tables:
//!
//! - `UNCONDITIONAL_SINKS` — `repr`, `builtins.repr`, `JSON.stringify`,
//!   `inspect` — every call is a debug leak by definition.
//! - `CONDITIONAL_SINKS` — `format!`, `println!`, `tracing::info!`,
//!   `log::warn`, `console.log`, … — these are debug-or-display
//!   depending on the format string. The
//!   `crate::helpers::call_uses_debug_format` predicate inspects the
//!   call's source span; if no debug-format placeholder appears the
//!   sink is skipped silently.

// `%r` and `{:?}` appear in user-facing remediation strings; they are
// not formatting placeholders here.
#![allow(clippy::literal_string_with_formatting_args)]

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    call_uses_debug_format, callee_matches, run_taint_rule, TaintRuleSpec, SOURCES_ANY,
};

/// Sinks whose mere presence with a tainted argument is a debug leak.
/// Callees here always reflect the value's full internal shape.
const UNCONDITIONAL_SINKS: &[&str] = &["repr", "builtins.repr", "JSON.stringify", "inspect"];

/// Format-string-aware sinks. Fire only when the call's source span
/// contains a debug-format placeholder (`{:?}`, `{:#?}`, `%r`, `!r`,
/// `.inspect`). Display-format calls (`format!("{}", x)`,
/// `tracing::info!("user={}", x)`) are skipped — `Display` is the
/// type's controlled, public representation, not a debug leak.
const CONDITIONAL_SINKS: &[&str] = &[
    "format",
    "format!",
    "println!",
    "eprintln!",
    "writeln!",
    "console.log",
    "console.debug",
    "console.error",
    "tracing::debug",
    "tracing::info",
    "tracing::warn",
    "tracing::error",
    "log::debug",
    "log::info",
    "log::warn",
    "log::error",
];

/// Combined sink table presented to [`run_taint_rule`]. Concatenates
/// [`UNCONDITIONAL_SINKS`] + [`CONDITIONAL_SINKS`] at compile time so
/// the two tables stay in sync. The [`format_aware_check`] predicate
/// disambiguates per call.
const SINKS_ARRAY: [&str; UNCONDITIONAL_SINKS.len() + CONDITIONAL_SINKS.len()] =
    const_concat_sinks();
const SINKS: &[&str] = &SINKS_ARRAY;

const fn const_concat_sinks() -> [&'static str; UNCONDITIONAL_SINKS.len() + CONDITIONAL_SINKS.len()]
{
    let mut out: [&'static str; UNCONDITIONAL_SINKS.len() + CONDITIONAL_SINKS.len()] =
        [""; UNCONDITIONAL_SINKS.len() + CONDITIONAL_SINKS.len()];
    let mut i = 0;
    while i < UNCONDITIONAL_SINKS.len() {
        out[i] = UNCONDITIONAL_SINKS[i];
        i += 1;
    }
    let mut j = 0;
    while j < CONDITIONAL_SINKS.len() {
        out[UNCONDITIONAL_SINKS.len() + j] = CONDITIONAL_SINKS[j];
        j += 1;
    }
    out
}

/// Sink-arg predicate. Returns `true` (= fire) when the matched callee
/// is in [`UNCONDITIONAL_SINKS`], OR when the call's source span uses a
/// debug-format placeholder. Returns `false` (= skip silently) for
/// Display-format calls so R-05 does not over-fire on every
/// `format!("{}", x)` in the kernel.
fn format_aware_check(
    batch: &cc_cpg::CpgWriteBatch,
    source: &dyn cc_rules::SourceTable,
    path: &camino::Utf8PathBuf,
    call: cc_cpg::NodeId,
    callee: &str,
) -> bool {
    if callee_matches(callee, UNCONDITIONAL_SINKS) {
        return true;
    }
    if callee_matches(callee, CONDITIONAL_SINKS) {
        return call_uses_debug_format(batch, source, path, call);
    }
    // Should never happen: callee already matched SINKS.
    false
}

/// Family-4 probe `cc.taint.repr_on_untrusted`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReprOnUntrustedRule;

impl Rule for ReprOnUntrustedRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.repr_on_untrusted"
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
        "tainted value passes through a debug-formatting sink (R-05)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.repr_on_untrusted",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 6,
                message: build_message,
                remediation: "Log only `type(value).__name__` plus length \
                              for untrusted input. Never `repr` / `%r` / \
                              `{:?}` / `JSON.stringify` an attacker-\
                              controlled value — debug formatters expose \
                              every byte the attacker supplied.",
                sink_arg_check: Some(format_aware_check),
                // Disable parameter seeding: most internal helpers take
                // a `&T` parameter and a `format!("{:?}", t)` on it is
                // diagnostic logging of an internal type, not an R-05
                // leak of attacker bytes. Real flows still fire via
                // explicit source-call seeding (request.GET → repr,
                // std::env::args → format!("{:?}", argv) etc.).
                seed_parameters: false,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted value passes through debug-formatter `{callee}` (R-05)");
    let body = format!(
        "Invariant R-05 forbids `repr` / `%r` / debug-format on \
         untrusted input — the full internal shape leaks back into logs \
         and traces. The value reaching `{callee}` originates from an \
         untrusted source on the same path."
    );
    (head, body)
}
