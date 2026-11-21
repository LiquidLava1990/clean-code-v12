//! [`run_rule`] — panic-safe, traced, confidence-filtered rule executor.
//!
//! The kernel never invokes [`Rule::run`] directly. Instead it goes
//! through this wrapper, which:
//!
//! 1. Opens a `tracing::info_span!("rule_run", rule_id, pack_id)` so
//!    per-rule timing falls out of the trace exporter for free.
//! 2. Catches panics with [`std::panic::catch_unwind`]; a panicking
//!    rule yields a single synthetic Meta finding rather than killing
//!    the kernel.
//! 3. Drops findings whose confidence is below the severity-tier
//!    threshold ([`Confidence::threshold_for`]).

use std::any::Any;
use std::panic::{self, AssertUnwindSafe};

use camino::Utf8PathBuf;
use cc_finding::{
    ActionableMessage, BigO, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};

use crate::context::RuleContext;
use crate::rule::{Rule, KERNEL_API_VERSION};

/// Run `rule` against `ctx`, returning its (filtered) findings.
///
/// `pack_id` is propagated into the trace span and into any synthetic
/// panic finding so operators can identify the misbehaving pack.
pub fn run_rule(rule: &dyn Rule, pack_id: &'static str, ctx: &RuleContext<'_>) -> Vec<Finding> {
    let span = tracing::info_span!("rule_run", rule_id = rule.rule_id(), pack_id = pack_id,);
    let _enter = span.enter();

    let findings = match panic::catch_unwind(AssertUnwindSafe(|| rule.run(ctx))) {
        Ok(findings) => findings,
        Err(payload) => {
            let message = panic_payload_to_string(&payload);
            return vec![meta_panic_finding(rule.rule_id(), pack_id, &message)];
        }
    };

    findings
        .into_iter()
        .filter(passes_confidence_threshold)
        .collect()
}

/// Drop findings whose confidence falls below the severity threshold.
fn passes_confidence_threshold(finding: &Finding) -> bool {
    let threshold = Confidence::threshold_for(finding.severity);
    finding.confidence.get() >= threshold
}

/// Render a panic payload to a printable string. Uses the `Display`
/// impl when the payload is a `String` / `&str`; otherwise falls back
/// to a fixed marker. We deliberately do NOT format with `{:?}` or
/// `{:#?}` — see global rule S10 (R-05 secret hygiene): never format
/// untrusted payloads with `Debug`.
fn panic_payload_to_string(payload: &Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_owned();
    }
    "non-string panic payload".to_owned()
}

/// Build the synthetic Meta finding emitted when a rule panics.
///
/// Construction goes through [`FindingBuilder`] so the rest of the
/// kernel sees a fully-validated finding (including a real
/// `SuppressKey`).
fn meta_panic_finding(rule_id: &'static str, pack_id: &'static str, message: &str) -> Finding {
    let headline = format!("rule {rule_id} panicked");
    let explanation = format!(
        "rule {rule_id} from pack {pack_id} raised a panic during run; \
         the kernel caught it and emitted this synthetic finding so the \
         scan could continue. Original panic message: {message}"
    );
    let remediation = Remediation::SuggestedRewrite(format!(
        "file a bug against pack {pack_id} including this finding's run_id; \
         disable rule {rule_id} via .cc/config.toml as a temporary mitigation"
    ));
    let location = sentinel_location();

    FindingBuilder::new()
        .rule_id("cc.meta.rule_panic")
        .category(Category::Meta)
        .subcategory("panic")
        .location(location)
        .message(ActionableMessage::new(headline, explanation, remediation))
        .evidence(Evidence::from_snippet(message))
        .severity(Severity::Blocker)
        .confidence(1.0)
        .cost(CostClaim::Asymptotic {
            order: BigO::O1,
            param: std::borrow::Cow::Borrowed("findings"),
            scenario: std::borrow::Cow::Borrowed("probe panic"),
        })
        .probe_version(ProbeVersion::new(
            "cc-rules",
            env!("CARGO_PKG_VERSION"),
            KERNEL_API_VERSION,
            None,
        ))
        .build()
        .expect("synthetic panic finding has all required fields")
}

/// Sentinel location used when a panic precludes obtaining a real one.
fn sentinel_location() -> Location {
    Location {
        file: Utf8PathBuf::from("<rule-panic>"),
        start: Position::new(1, 1, 0),
        end: Position::new(1, 1, 0),
        node_id: None,
        function_qualified_name: None,
    }
}
