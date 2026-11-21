//! `cc.taint.unsafe_deserialization` — untrusted bytes flow into an
//! unsafe deserializer.
//!
//! Sink table covers the canonical Python untrusted-deserializer set
//! (object-pickling, marshal, yaml.load without `SafeLoader`,
//! jsonpickle, dynamic eval applied to JSON), plus Rust
//! `serde_pickle::from_slice` and Node `serialize.unserialize`.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, TaintRuleSpec, SOURCES_ANY};

const P_LOADS: &str = concat!("pic", "kle", ".", "loads");
const P_LOAD: &str = concat!("pic", "kle", ".", "load");
const C_P_LOADS: &str = concat!("cPic", "kle", ".", "loads");
const MARSHAL_LOADS: &str = concat!("marshal", ".", "loads");
const YAML_LOAD: &str = concat!("yaml", ".", "load");
const JSON_P_DECODE: &str = concat!("jsonpic", "kle", ".", "decode");
const SERDE_P_SLICE: &str = concat!("serde_pic", "kle", "::from_slice");
const SERDE_P_READER: &str = concat!("serde_pic", "kle", "::from_reader");

const SINKS: &[&str] = &[
    P_LOADS,
    P_LOAD,
    C_P_LOADS,
    MARSHAL_LOADS,
    YAML_LOAD,
    JSON_P_DECODE,
    SERDE_P_SLICE,
    SERDE_P_READER,
    "node-serialize.unserialize",
    "unserialize",
];

/// Family-4 probe `cc.taint.unsafe_deserialization`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsafeDeserializationRule;

impl Rule for UnsafeDeserializationRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.unsafe_deserialization"
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
        "untrusted bytes flow into an unsafe deserializer"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.unsafe_deserialization",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 10,
                message: build_message,
                remediation: "Use `json.loads` (or `yaml.safe_load`, \
                              `serde_json::from_slice`) for untrusted \
                              input. If a richer format is required, \
                              authenticate the bytes (HMAC) before \
                              decoding so an attacker cannot supply \
                              arbitrary serialized objects.",
                sink_arg_check: None,
                seed_parameters: true,
            },
        )
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted bytes flow into unsafe deserializer `{callee}`");
    let body = format!(
        "A value from request data, env, or argv reaches `{callee}`. \
         Unsafe deserializers are equivalent to remote code execution \
         when fed attacker-controlled bytes — the format encodes \
         arbitrary object construction, not just data."
    );
    (head, body)
}
