//! `cc.arch.god_module_imports` — single file with too many imports.
//!
//! A module that imports more than 30 other modules is doing too much.
//! It either coordinates a fan-out wider than any human can hold in
//! mental cache (god dispatcher) or has accreted unrelated
//! responsibilities. Across languages this manifests as:
//!
//! - **Python**: `import` count > 30
//! - **Rust**: `use` count > 30
//! - **TypeScript / JavaScript**: `import` count > 30
//!
//! Sister probe to [`crate::fan_out_outlier`] — that rule uses the
//! resolved import graph (unique target modules per source). This rule
//! is a raw textual / AST count: every `Import` AST node in the file
//! contributes, regardless of resolution success.
//!
//! OSS source: Sonar `python:S107` / `S138` (cognitive-complexity for
//! imports), pylint R0914 (variants), ESLint `import/max-dependencies`,
//! clippy `too_many_lines` (analogous god-file rule).

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, enclosing_file_id, ArchitectureFindingBlueprint};

/// Family-20 probe `cc.arch.god_module_imports`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GodModuleImportsRule;

/// Threshold above which a single file's import count is considered
/// pathological. Mirrors `fan_out_outlier` doctrine.
pub const DEFAULT_IMPORT_THRESHOLD: usize = 30;

impl Rule for GodModuleImportsRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.god_module_imports"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "single file declares too many imports — module is doing too much"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let counts = build_per_file_counts(ctx);
        emit_findings_above_threshold(ctx, &counts)
    }
}

/// Map `File` node id → number of `Import` AST descendants whose
/// enclosing file is that node. Files with zero imports are absent from
/// the map.
fn build_per_file_counts(
    ctx: &RuleContext<'_>,
) -> std::collections::BTreeMap<u64, (NodeId, usize)> {
    let mut counts: std::collections::BTreeMap<u64, (NodeId, usize)> =
        std::collections::BTreeMap::new();
    for import_node in nodes_of_kind(ctx.batch, NodeKind::Import) {
        let Some(file_id) = enclosing_file_id(ctx.batch, import_node.id) else {
            continue;
        };
        counts
            .entry(file_id.get())
            .and_modify(|entry| entry.1 += 1)
            .or_insert((file_id, 1));
    }
    counts
}

/// True iff `path` is a registry-shaped file whose import count is
/// expected to be high by design (rule packs, test aggregators,
/// `mod.rs` re-exports). Skipping these avoids flagging the legitimate
/// "register every probe" pattern.
fn is_registry_file(path: &Utf8PathBuf) -> bool {
    let stem = path
        .file_stem()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        stem.as_str(),
        "pack" | "tests" | "mod" | "lib" | "registry" | "main"
    )
}

fn emit_findings_above_threshold(
    ctx: &RuleContext<'_>,
    counts: &std::collections::BTreeMap<u64, (NodeId, usize)>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_, (file_id, count)) in counts {
        if *count <= DEFAULT_IMPORT_THRESHOLD {
            continue;
        }
        let Some(path) = string_prop(ctx.batch, *file_id, "path").map(Utf8PathBuf::from) else {
            continue;
        };
        if is_registry_file(&path) {
            continue;
        }
        out.push(emit(path, *count));
    }
    out
}

fn emit(path: Utf8PathBuf, count: usize) -> Finding {
    let pos = Position::new(1, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.god_module_imports",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        related: Vec::new(),
        headline: format!(
            "module declares {count} imports (>{DEFAULT_IMPORT_THRESHOLD}) — \
             responsibilities are too broad"
        ),
        explanation: "A single module that pulls in more than \
             30 other modules is fanning out beyond what an engineer \
             can hold in mental cache. Either the file has accreted \
             unrelated responsibilities or it is a god dispatcher \
             coordinating too many subsystems. Both shapes destroy \
             change isolation: editing the file requires understanding \
             every imported subsystem at once."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Split the file along its responsibility seams. Common moves: \
             extract domain entities into a sibling module; pull \
             integration adapters into a sub-package and re-export; \
             collapse 'wrapper' imports that just re-export a \
             single symbol."
                .into(),
        ),
        snippet: format!("imports={count}"),
        weight: 4,
    })
}
