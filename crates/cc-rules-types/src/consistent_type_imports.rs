//! `cc.type.consistent_type_imports` — value-import of a name that is
//! only ever used in type position.
//!
//! Syntactic shadow of TypeScript ESLint's `consistent-type-imports`.
//! When an imported name is consumed only by type positions
//! (`: Foo`, `as Foo`, `<Foo>`, `extends Foo`, `implements Foo`), the
//! import should be `import type { Foo }` so the bundler can drop it
//! at compile time.
//!
//! Detection:
//!
//! 1. Read the file source from `ctx.source` (TS/TSX only).
//! 2. Parse simple `import { A, B } from 'mod'` lines (skip
//!    `import type { ... }` and side-effect imports).
//! 3. For each imported name, scan the rest of the file for any non-
//!    type-position use. If every use is a type position, flag.
//!
//! This is text-based (no AST), so it stays robust to frontend property
//! coverage. The trade-off: complex imports (`import * as ns`,
//! re-exports, JSX components) are skipped to avoid false positives.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, file_source_text,
    is_test_file_path, location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-CONSISTENT-TYPE-IMPORTS.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsistentTypeImportsRule;

impl Rule for ConsistentTypeImportsRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.consistent_type_imports"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "value-import of a name only used in type position"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            check_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn check_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(prep) = prepare_file(ctx, file_id) else {
        return;
    };
    let imports = parse_value_imports(&prep.source);
    if imports.is_empty() {
        return;
    }
    for import in imports {
        if !is_type_only_use(&prep.source, &import.name) {
            continue;
        }
        let location = location_from_node(ctx.batch, file_id, prep.path.clone());
        out.push(build_import_finding(&import, location));
    }
}

struct PreparedFile {
    path: camino::Utf8PathBuf,
    source: String,
}

fn prepare_file(ctx: &RuleContext<'_>, file_id: NodeId) -> Option<PreparedFile> {
    let language = enclosing_file_language(ctx.batch, file_id)?;
    if !is_typescript(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, file_id)?;
    if !is_ts_extension(path.as_str()) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let bytes = file_source_text(ctx, &path)?;
    let source = std::str::from_utf8(bytes).ok()?.to_owned();
    Some(PreparedFile { path, source })
}

fn build_import_finding(import: &ParsedImport, location: cc_finding::Location) -> Finding {
    build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.consistent_type_imports",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "import `{name}` from `{module}` is only used as a type",
            name = import.name,
            module = import.module,
        ),
        explanation: format!(
            "`{name}` is imported as a value but every use in this file is \
             a type position (`: {name}`, `as {name}`, `<{name}>`, `extends \
             {name}`, `implements {name}`). Mark the import `import type` \
             so the bundler can drop it at compile time.",
            name = import.name,
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Change `import {{ {name} }} from '{module}'` to `import type \
             {{ {name} }} from '{module}'`. If the module mixes type-only \
             and value-only members, split the import.",
            name = import.name,
            module = import.module,
        )),
        snippet: format!("import {{ {} }} from '{}'", import.name, import.module),
        weight: 1,
    })
}

#[derive(Debug, Clone)]
struct ParsedImport {
    name: String,
    module: String,
}

fn parse_value_imports(source: &str) -> Vec<ParsedImport> {
    let mut out = Vec::new();
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if !line.starts_with("import ") || line.starts_with("import type ") {
            continue;
        }
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let Some((names_part, module_part)) = split_named_import(rest) else {
            continue;
        };
        for raw in names_part.split(',') {
            if let Some(name) = clean_name(raw) {
                out.push(ParsedImport {
                    name,
                    module: module_part.clone(),
                });
            }
        }
    }
    out
}

fn split_named_import(rest: &str) -> Option<(&str, String)> {
    let open = rest.find('{')?;
    let close = rest.find('}')?;
    if close <= open {
        return None;
    }
    let names_part = rest.get(open + 1..close)?;
    let after = rest.get(close + 1..)?;
    let from_pos = after.find("from")?;
    let after_from = after.get(from_pos + 4..)?.trim();
    let module = strip_quotes(after_from)?;
    Some((names_part, module))
}

fn strip_quotes(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_end_matches(';').trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !matches!(first, b'\'' | b'"') || first != last {
        return None;
    }
    Some(trimmed.get(1..bytes.len() - 1)?.to_owned())
}

fn clean_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains(" as ") || trimmed.contains('*') {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    Some(trimmed.to_owned())
}

fn is_type_only_use(source: &str, name: &str) -> bool {
    let mut value_uses = 0_u32;
    let mut type_uses = 0_u32;
    for (idx, _) in source.match_indices(name) {
        if !is_word_boundary(source, idx, name.len()) {
            continue;
        }
        if is_inside_import_line(source, idx) {
            continue;
        }
        if is_type_position(source, idx, name.len()) {
            type_uses += 1;
        } else {
            value_uses += 1;
        }
    }
    type_uses > 0 && value_uses == 0
}

fn is_word_boundary(source: &str, idx: usize, len: usize) -> bool {
    let bytes = source.as_bytes();
    let before_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
    let after_ok = idx + len >= bytes.len() || !is_ident_byte(bytes[idx + len]);
    before_ok && after_ok
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn is_inside_import_line(source: &str, idx: usize) -> bool {
    let line_start = source[..idx].rfind('\n').map_or(0, |p| p + 1);
    let line_end = source[idx..].find('\n').map_or(source.len(), |p| p + idx);
    let line = source.get(line_start..line_end).unwrap_or("");
    line.trim_start().starts_with("import")
}

fn is_type_position(source: &str, idx: usize, len: usize) -> bool {
    let bytes = source.as_bytes();
    let before = preceding_significant(bytes, idx);
    if matches!(before, Some(b':' | b'<')) {
        return true;
    }
    if let Some(token) = preceding_token(source, idx) {
        if matches!(
            token,
            "extends" | "implements" | "as" | "satisfies" | "type" | "interface"
        ) {
            return true;
        }
    }
    let after_idx = idx + len;
    let after = following_significant(bytes, after_idx);
    if after == Some(b'>') && has_open_angle_within(bytes, idx) {
        return true;
    }
    false
}

fn preceding_significant(bytes: &[u8], idx: usize) -> Option<u8> {
    let mut i = idx;
    while i > 0 {
        i -= 1;
        let b = bytes[i];
        if b == b' ' || b == b'\t' {
            continue;
        }
        return Some(b);
    }
    None
}

fn following_significant(bytes: &[u8], idx: usize) -> Option<u8> {
    let mut i = idx;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        return Some(b);
    }
    None
}

fn preceding_token(source: &str, idx: usize) -> Option<&str> {
    let prefix = source.get(..idx)?.trim_end();
    let last_space = prefix
        .rfind(|c: char| c.is_whitespace())
        .map_or(0, |p| p + 1);
    let token = prefix.get(last_space..)?;
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn has_open_angle_within(bytes: &[u8], idx: usize) -> bool {
    let start = idx.saturating_sub(64);
    for i in (start..idx).rev() {
        match bytes[i] {
            b'<' => return true,
            b'=' | b'\n' | b';' => return false,
            _ => {}
        }
    }
    false
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}
