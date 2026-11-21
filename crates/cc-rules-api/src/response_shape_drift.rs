//! `cc.api.response_shape_drift` — handler returns inconsistent shapes.
//!
//! Heuristic: walk every public [`NodeKind::Function`] / [`NodeKind::Method`]
//! whose name or `return_type` matches one of the canonical handler
//! markers (`crate::helpers::HANDLER_NAME_PATTERNS` /
//! `crate::helpers::RESPONSE_TYPE_PATTERNS`). For each such function,
//! collect every [`NodeKind::Return`] node whose `range` falls inside
//! the function's `range`. Compute a coarse signature for each return
//! by tokenising its source-byte slice on `{` / `,` / `:` / `}` and
//! sorting the captured field names. Two returns with different
//! sorted-field-set signatures imply the handler emits structurally
//! different shapes — a real-world source of client breakage.
//!
//! Phase-4 simplification: the signature is intentionally *coarse* —
//! it counts and names top-level keys in object-literal returns and
//! treats non-object returns as a single sentinel. A more precise
//! Phase-5 implementation will lift the return expression to a typed
//! shape via the persistent CPG store.

use std::collections::BTreeSet;

use camino::Utf8PathBuf;
use cc_cpg::{Node, NodeId, NodeKind, Range};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, looks_like_handler,
    ApiFindingBlueprint,
};

/// Family-9 probe R-API-RESPONSE-SHAPE-DRIFT.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseShapeDriftRule;

impl Rule for ResponseShapeDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.response_shape_drift"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.65)
    }
    fn description(&self) -> &'static str {
        "handler returns structurally different shapes from different return statements"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = scan_for_shape_drift(ctx, node) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn scan_for_shape_drift(ctx: &RuleContext<'_>, func: &Node) -> Option<Finding> {
    let name = string_prop(ctx.batch, func.id, "name");
    let return_type = string_prop(ctx.batch, func.id, "return_type");
    if !looks_like_handler(name, return_type) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, func.id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let func_range = range_prop(ctx.batch, func.id, "range")?;
    let signatures = collect_return_signatures(ctx, func_range, &path);
    if signatures.len() < 2 {
        return None;
    }
    let location = location_from_node(ctx.batch, func.id, path);
    Some(emit(name.unwrap_or("<anonymous>"), location, &signatures))
}

/// Collect a deduplicated set of return signatures for every Return
/// node whose range lies within `func_range`.
fn collect_return_signatures(
    ctx: &RuleContext<'_>,
    func_range: Range,
    path: &Utf8PathBuf,
) -> BTreeSet<String> {
    let bytes = ctx.source.get(path);
    let mut sigs = BTreeSet::new();
    for ret in nodes_of_kind(ctx.batch, NodeKind::Return) {
        let Some(ret_range) = range_prop(ctx.batch, ret.id, "range") else {
            continue;
        };
        if !range_contains(func_range, ret_range) {
            continue;
        }
        let Some(sig) = signature_for_return(ret.id, ret_range, bytes, ctx) else {
            continue;
        };
        sigs.insert(sig);
    }
    sigs
}

/// True iff `inner` lies entirely within `outer` (inclusive).
const fn range_contains(outer: Range, inner: Range) -> bool {
    inner.start.offset >= outer.start.offset && inner.end.offset <= outer.end.offset
}

/// Coarse Phase-4 signature: prefer an explicit `signature` string
/// property if the frontend supplies one; otherwise tokenise the
/// return expression's source bytes into a sorted set of field names.
fn signature_for_return(
    id: NodeId,
    range: Range,
    bytes: &[u8],
    ctx: &RuleContext<'_>,
) -> Option<String> {
    if let Some(explicit) = string_prop(ctx.batch, id, "signature") {
        return Some(explicit.to_owned());
    }
    let start = range.start.offset as usize;
    let end = (range.end.offset as usize).min(bytes.len());
    if start >= end {
        return None;
    }
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?;
    Some(return_arg_signature(text))
}

/// Tokenise a return expression's source text into a coarse signature.
///
/// Object-literal returns yield `{field_a,field_b,field_c}` (sorted);
/// non-object returns yield a `scalar:<token>` sentinel so two scalar
/// returns of the same shape collapse to a single signature.
pub(crate) fn return_arg_signature(text: &str) -> String {
    let trimmed = text.trim_start_matches("return").trim();
    if let Some(fields) = extract_object_fields(trimmed) {
        return format!("{{{}}}", join_sorted(fields));
    }
    let token = trimmed
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();
    format!(
        "scalar:{}",
        if token.is_empty() {
            "<empty>"
        } else {
            token.as_str()
        }
    )
}

/// If `text` opens with an object literal (`{...}` / `dict(...)` /
/// `Json(...)`), return the deduplicated set of top-level keys.
fn extract_object_fields(text: &str) -> Option<BTreeSet<String>> {
    let body = strip_object_wrapper(text)?;
    let mut fields = BTreeSet::new();
    for chunk in body.split(',') {
        let key = chunk.split(':').next().unwrap_or("").trim();
        let key = key.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
        if key.is_empty() {
            continue;
        }
        fields.insert(key.to_owned());
    }
    Some(fields)
}

/// Strip a leading `{` / `Json(` / `dict(` wrapper, returning the
/// inner key-value text, or `None` when no recognisable wrapper is
/// present.
fn strip_object_wrapper(text: &str) -> Option<&str> {
    if let Some(rest) = text.strip_prefix('{') {
        return Some(rest.trim_end_matches('}'));
    }
    for prefix in ["Json(", "JsonResponse(", "dict(", "Response::ok("] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Some(rest.trim_end_matches(')'));
        }
    }
    None
}

fn join_sorted(fields: BTreeSet<String>) -> String {
    fields.into_iter().collect::<Vec<_>>().join(",")
}

fn emit(name: &str, location: cc_finding::Location, signatures: &BTreeSet<String>) -> Finding {
    let snippet = signatures
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    build_finding(ApiFindingBlueprint {
        rule_id: "cc.api.response_shape_drift",
        severity: Severity::Required,
        confidence: Confidence::new(0.65),
        location,
        headline: format!(
            "handler `{name}` returns {} structurally different shapes",
            signatures.len()
        ),
        explanation: format!(
            "Handler `{name}` has multiple `return` statements that emit \
             objects with different field sets. Clients written against \
             one branch break silently on the other — a missing field \
             surfaces as `undefined` / `KeyError` only when the alternate \
             branch fires. Make every branch return the same shape \
             (omitted fields explicitly null), or split the handler so \
             each shape has its own typed endpoint."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Define a typed response struct and construct it on every \
             return path; if the shape genuinely varies (e.g. error vs \
             success), wrap it in a tagged union (`Result` / discriminated \
             union) so clients see the variance in the type system."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
