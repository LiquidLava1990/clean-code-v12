//! Pure-function mapping from `cc-finding::Finding` to [`SarifDocument`].

use std::collections::{BTreeMap, BTreeSet};

use cc_finding::{
    fix::{FixProposal, Range, TextEdit},
    Finding, Severity,
};
use serde_json::json;

use crate::doc::{
    ArtifactChange, ArtifactContent, ArtifactLocation, Fix, Location, Message,
    MultiformatMessageString, PhysicalLocation, Region, Replacement, ReportingConfiguration,
    ReportingDescriptor, Run, SarifDocument, SarifResult, Tool, ToolComponent, SARIF_SCHEMA_URI,
    SARIF_VERSION,
};

/// Tool-driver metadata supplied by the caller (typically cc-cli).
#[derive(Debug, Clone, Copy)]
pub struct ToolMeta {
    /// Display name.
    pub name: &'static str,
    /// Producer semver.
    pub version: &'static str,
    /// Public docs URL.
    pub information_uri: &'static str,
    /// Per-rule docs URL prefix; cc-sarif appends `{family}/{rule_id}.md`.
    /// Pass `""` to skip emitting `helpUri`.
    pub help_uri_prefix: &'static str,
}

impl ToolMeta {
    /// Default cc-kernel metadata. Useful for tests + cc-cli wiring.
    #[must_use]
    pub const fn cc_kernel() -> Self {
        Self {
            name: "clean-code-v12",
            version: env!("CARGO_PKG_VERSION"),
            information_uri: "https://github.com/LiquidLava1990/clean-code-v12",
            help_uri_prefix: "https://cleancode.dev/docs/rules",
        }
    }
}

/// Build a [`SarifDocument`] from a slice of findings.
///
/// Pure — no I/O. Caller is responsible for serialising the result.
#[must_use]
pub fn to_sarif(findings: &[Finding], tool_meta: ToolMeta) -> SarifDocument {
    let rules = build_rules(findings, &tool_meta);
    let results = findings.iter().map(map_finding).collect();
    let driver = ToolComponent {
        name: tool_meta.name.to_owned(),
        version: tool_meta.version.to_owned(),
        information_uri: optional_string(tool_meta.information_uri),
        rules,
    };
    let run = Run {
        tool: Tool { driver },
        results,
        invocations: None,
        original_uri_base_ids: None,
    };
    SarifDocument {
        schema: SARIF_SCHEMA_URI.to_owned(),
        version: SARIF_VERSION.to_owned(),
        runs: vec![run],
    }
}

fn optional_string(s: &'static str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn build_rules(findings: &[Finding], meta: &ToolMeta) -> Vec<ReportingDescriptor> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut by_id: BTreeMap<String, ReportingDescriptor> = BTreeMap::new();
    for f in findings {
        let id = f.rule_id.as_ref().to_owned();
        if !seen.insert(id.clone()) {
            continue;
        }
        by_id.insert(id.clone(), build_descriptor(&id, f.severity, meta));
    }
    by_id.into_values().collect()
}

fn build_descriptor(rule_id: &str, sev: Severity, meta: &ToolMeta) -> ReportingDescriptor {
    let family = rule_family(rule_id);
    let help_uri = if meta.help_uri_prefix.is_empty() {
        None
    } else {
        Some(format!(
            "{}/{}/{}.md",
            meta.help_uri_prefix.trim_end_matches('/'),
            family,
            rule_id
        ))
    };
    ReportingDescriptor {
        id: rule_id.to_owned(),
        name: Some(rule_id.to_owned()),
        short_description: Some(MultiformatMessageString {
            text: format!("see `cc explain {rule_id}` for details"),
            markdown: None,
        }),
        full_description: None,
        help_uri,
        default_configuration: Some(ReportingConfiguration {
            level: sev.sarif_level().to_owned(),
            enabled: Some(true),
        }),
    }
}

/// Extract the family segment from a rule id like `cc.shape.fn_length`.
/// Returns `"unknown"` when the id has fewer than 2 dot-separated segments.
fn rule_family(rule_id: &str) -> &str {
    let mut parts = rule_id.split('.');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    if second.is_empty() {
        if first.is_empty() {
            "unknown"
        } else {
            first
        }
    } else {
        second
    }
}

fn map_finding(f: &Finding) -> SarifResult {
    let location = build_primary_location(f);
    let related = f.related.iter().map(build_related_location).collect();
    let mut partial_fingerprints = BTreeMap::new();
    partial_fingerprints.insert("cc/v1".to_owned(), f.suppress_key.to_hex());

    SarifResult {
        rule_id: f.rule_id.as_ref().to_owned(),
        level: f.severity.sarif_level().to_owned(),
        message: build_message(f),
        locations: vec![location],
        related_locations: related,
        partial_fingerprints,
        fingerprints: BTreeMap::new(),
        fixes: build_fixes(f),
        properties: build_properties(f),
    }
}

fn build_message(f: &Finding) -> Message {
    Message {
        text: f.message.headline.clone(),
        markdown: Some(format!(
            "**{}**\n\n{}",
            f.message.headline, f.message.explanation
        )),
    }
}

fn build_primary_location(f: &Finding) -> Location {
    Location {
        physical_location: build_physical(&f.location, &f.evidence.snippet),
        message: None,
    }
}

fn build_related_location(rel: &cc_finding::RelatedLocation) -> Location {
    Location {
        physical_location: build_physical(&rel.location, ""),
        message: Some(Message {
            text: rel.message.clone(),
            markdown: None,
        }),
    }
}

fn build_physical(loc: &cc_finding::Location, snippet: &str) -> PhysicalLocation {
    let region = build_region(loc, snippet);
    PhysicalLocation {
        artifact_location: ArtifactLocation {
            uri: loc.file.as_str().replace('\\', "/"),
            uri_base_id: Some("%SRCROOT%".to_owned()),
        },
        region,
    }
}

fn build_region(loc: &cc_finding::Location, snippet: &str) -> Region {
    let byte_length = loc.end.offset.checked_sub(loc.start.offset);
    let snippet_field = if snippet.is_empty() {
        None
    } else {
        Some(ArtifactContent {
            text: snippet.to_owned(),
        })
    };
    Region {
        start_line: loc.start.line,
        start_column: Some(loc.start.column),
        end_line: Some(loc.end.line),
        end_column: Some(loc.end.column),
        byte_offset: Some(loc.start.offset),
        byte_length,
        snippet: snippet_field,
    }
}

fn build_fixes(f: &Finding) -> Vec<Fix> {
    let Some(proposal) = f.fix.as_ref() else {
        return Vec::new();
    };
    match proposal {
        FixProposal::Diff { edits, .. } => vec![diff_to_fix(f, edits)],
        FixProposal::Codemod {
            pattern,
            replacement,
            ..
        } => vec![codemod_to_fix(f, pattern, replacement)],
        FixProposal::LlmRewrite { .. } => Vec::new(),
    }
}

fn diff_to_fix(f: &Finding, edits: &[TextEdit]) -> Fix {
    let replacements = edits.iter().map(text_edit_to_replacement).collect();
    build_fix(
        format!("auto-fix for {}", f.rule_id),
        f.location.file.as_str(),
        replacements,
    )
}

fn codemod_to_fix(f: &Finding, pattern: &str, replacement: &str) -> Fix {
    let region = Region {
        start_line: f.location.start.line,
        start_column: Some(f.location.start.column),
        end_line: Some(f.location.end.line),
        end_column: Some(f.location.end.column),
        byte_offset: Some(f.location.start.offset),
        byte_length: f.location.end.offset.checked_sub(f.location.start.offset),
        snippet: Some(ArtifactContent {
            text: pattern.to_owned(),
        }),
    };
    let replacements = vec![Replacement {
        deleted_region: region,
        inserted_content: Some(ArtifactContent {
            text: replacement.to_owned(),
        }),
    }];
    build_fix(
        format!("codemod replace for {}", f.rule_id),
        f.location.file.as_str(),
        replacements,
    )
}

/// Build a SARIF [`Fix`] with the standard description-message +
/// single-artifact-change envelope. Both `diff_to_fix` and
/// `codemod_to_fix` differ only in the description text and how they
/// derive replacements; everything else (URI normalisation, base id,
/// envelope shape) is identical and lives here.
fn build_fix(description_text: String, file_uri: &str, replacements: Vec<Replacement>) -> Fix {
    Fix {
        description: Message {
            text: description_text,
            markdown: None,
        },
        artifact_changes: vec![ArtifactChange {
            artifact_location: ArtifactLocation {
                uri: file_uri.replace('\\', "/"),
                uri_base_id: Some("%SRCROOT%".to_owned()),
            },
            replacements,
        }],
    }
}

fn text_edit_to_replacement(edit: &TextEdit) -> Replacement {
    Replacement {
        deleted_region: range_to_region(&edit.range),
        inserted_content: if edit.new_text.is_empty() {
            None
        } else {
            Some(ArtifactContent {
                text: edit.new_text.clone(),
            })
        },
    }
}

const fn range_to_region(range: &Range) -> Region {
    Region {
        start_line: range.start.line,
        start_column: Some(range.start.column),
        end_line: Some(range.end.line),
        end_column: Some(range.end.column),
        byte_offset: Some(range.start.offset),
        byte_length: range.end.offset.checked_sub(range.start.offset),
        snippet: None,
    }
}

fn build_properties(f: &Finding) -> serde_json::Value {
    let mut props = json!({
        "category": f.category.as_str(),
        "confidence": f.confidence.get(),
        "cost": f.cost,
        "kernel_version": f.kernel_version,
        "probe_version": f.probe_version,
    });
    if let Some(sub) = &f.subcategory {
        props["subcategory"] = json!(sub.as_ref());
    }
    if let Some(FixProposal::LlmRewrite {
        original,
        proposed,
        rationale,
        prompt_hash,
    }) = f.fix.as_ref()
    {
        props["suggested_rewrite"] = json!({
            "original": original,
            "proposed": proposed,
            "rationale": rationale,
            "prompt_hash": prompt_hash,
        });
    }
    if let Some(gr) = &f.introduced_at {
        props["introduced_at"] = json!(gr);
    }
    props
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_extraction() {
        assert_eq!(rule_family("cc.shape.fn_length"), "shape");
        assert_eq!(rule_family("cc.taint.sql_injection"), "taint");
        assert_eq!(rule_family("plain"), "plain");
        assert_eq!(rule_family(""), "unknown");
    }
}
