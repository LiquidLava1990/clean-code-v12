//! `cc.type.exhaustruct` — Go struct literal missing one or more
//! declared fields.
//!
//! Syntactic shadow of golangci-lint's `exhaustruct`; full version
//! requires cross-file type resolution. We approximate single-file
//! Go: when a `Class` (struct) declared in this file is instantiated
//! by a struct literal recorded as a [`NodeKind::Call`] with
//! `kind == "struct_literal"`, we compare the literal's `fields_set`
//! string property against the struct's `fields_declared` and emit a
//! finding for every missing field whose declared type is non-zeroable
//! (anything other than the basic numerics, booleans, strings, and
//! pointer types).
//!
//! Cross-file struct types are skipped by design — false-positives on
//! partial CPGs would dwarf true positives.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-EXHAUSTRUCT.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExhaustructRule;

impl Rule for ExhaustructRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.exhaustruct"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Go struct literal missing one or more declared non-zeroable fields"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_struct_literal(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_struct_literal(ctx: &RuleContext<'_>, call_id: NodeId) -> Option<Finding> {
    let kind = string_prop(ctx.batch, call_id, "kind").unwrap_or("");
    if kind != "struct_literal" {
        return None;
    }
    let language = enclosing_file_language(ctx.batch, call_id)?;
    if !is_go(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let type_name = string_prop(ctx.batch, call_id, "type_name")?;
    let file_id = enclosing_file_id(ctx, call_id)?;
    let struct_node = find_struct_declaration(ctx, file_id, type_name)?;
    let declared = parse_field_list(string_prop(ctx.batch, struct_node.id, "fields_declared")?);
    if declared.is_empty() {
        return None;
    }
    let set = parse_field_list(string_prop(ctx.batch, call_id, "fields_set").unwrap_or(""));
    let missing = collect_missing_nonzero(&declared, &set);
    if missing.is_empty() {
        return None;
    }
    let location = location_from_node(ctx.batch, call_id, path);
    let detail = missing.join(", ");
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.exhaustruct",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{type_name}{{...}}` omits non-zeroable fields: {detail}"),
        explanation: format!(
            "The struct literal for `{type_name}` does not set {detail}. \
             Go silently zeroes missing fields, so non-zeroable values \
             (slices, maps, channels, interfaces, function-typed fields) \
             default to nil and dereferencing them panics at runtime."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Set every non-zeroable field explicitly: `{type_name}{{ {detail}: \
             ..., ... }}`. If the zero value is intended, mark it via a \
             constructor that documents the policy (`New{type_name}()`)."
        )),
        snippet: type_name.to_owned(),
        weight: 2,
    }))
}

fn is_go(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "go")
}

fn enclosing_file_id(ctx: &RuleContext<'_>, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        if node_kind(ctx.batch, id) == Some(NodeKind::File) {
            return Some(id);
        }
        id = ast_parent(ctx.batch, id)?;
    }
    None
}

fn find_struct_declaration<'b>(
    ctx: &'b RuleContext<'b>,
    file_id: NodeId,
    type_name: &str,
) -> Option<&'b Node> {
    nodes_of_kind(ctx.batch, NodeKind::Class).find(|node| {
        if !descends_from(ctx, node.id, file_id) {
            return false;
        }
        string_prop(ctx.batch, node.id, "name") == Some(type_name)
    })
}

fn descends_from(ctx: &RuleContext<'_>, mut id: NodeId, target: NodeId) -> bool {
    for _ in 0..256_u16 {
        if id == target {
            return true;
        }
        match ast_parent(ctx.batch, id) {
            Some(parent) => id = parent,
            None => return false,
        }
    }
    false
}

fn parse_field_list(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in text.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, ty) = entry.split_once(':').unwrap_or((entry, ""));
        out.push((name.trim().to_owned(), ty.trim().to_owned()));
    }
    out
}

fn collect_missing_nonzero(declared: &[(String, String)], set: &[(String, String)]) -> Vec<String> {
    let mut missing: Vec<String> = Vec::new();
    for (name, ty) in declared {
        let already_set = set.iter().any(|(n, _)| n == name);
        if already_set {
            continue;
        }
        if zero_safe(ty) {
            continue;
        }
        missing.push(name.clone());
    }
    missing
}

fn zero_safe(ty: &str) -> bool {
    let trimmed = ty.trim();
    if trimmed.is_empty() || trimmed.starts_with('*') {
        return true;
    }
    matches!(
        trimmed,
        "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
            | "float32"
            | "float64"
            | "complex64"
            | "complex128"
            | "bool"
            | "string"
            | "byte"
            | "rune"
            | "error"
    )
}
