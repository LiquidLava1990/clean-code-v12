//! `cc.modernize.banned_import_alias` — `import numpy as numpy` (stutter)
//! / `import pandas as panda` (typo). Aliases must match the canonical
//! community convention so cross-codebase reads carry zero cognitive
//! load.
//!
//! Mirrors ruff `ICN001` (unconventional-import-alias).
//!
//! Phase-9 detector: scan every Python file once for `import <module>
//! as <alias>` lines. For each entry in `CANONICAL_ALIASES`, if the
//! actual `<alias>` differs from the canonical one (or duplicates the
//! module name unnecessarily), flag.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.banned_import_alias`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BannedImportAliasRule;

/// Canonical community aliases. `(module, expected_alias)`.
pub(crate) const CANONICAL_ALIASES: &[(&str, &str)] = &[
    ("altair", "alt"),
    ("matplotlib.pyplot", "plt"),
    ("networkx", "nx"),
    ("numpy", "np"),
    ("pandas", "pd"),
    ("seaborn", "sns"),
    ("statsmodels.api", "sm"),
    ("tensorflow", "tf"),
    ("xarray", "xr"),
];

impl Rule for BannedImportAliasRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.banned_import_alias"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Python import alias diverges from the canonical convention"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(violation) = find_alias_violation(line) {
            out.push(emit(path.clone(), line_idx + 1, line, violation));
        }
    }
}

#[derive(Debug)]
struct AliasViolation {
    module: &'static str,
    actual: String,
    expected: &'static str,
}

fn find_alias_violation(line: &str) -> Option<AliasViolation> {
    let trimmed = line.trim_start();
    let after_import = trimmed.strip_prefix("import ")?;
    let (module, alias) = split_import_as(after_import)?;
    for (canon_module, canon_alias) in CANONICAL_ALIASES {
        if module == *canon_module && alias != *canon_alias {
            return Some(AliasViolation {
                module: canon_module,
                actual: alias.to_owned(),
                expected: canon_alias,
            });
        }
    }
    None
}

fn split_import_as(rest: &str) -> Option<(&str, &str)> {
    let as_idx = rest.find(" as ")?;
    let module = rest[..as_idx].trim();
    let after_as = rest[as_idx + 4..].trim();
    let alias_end = after_as
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(after_as.len());
    let alias = &after_as[..alias_end];
    if module.is_empty() || alias.is_empty() {
        return None;
    }
    Some((module, alias))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, violation: AliasViolation) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let AliasViolation {
        module,
        actual,
        expected,
    } = violation;
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.banned_import_alias",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`import {module} as {actual}` — convention is `as {expected}`"),
        explanation: format!(
            "Community-wide convention aliases `{module}` as `{expected}`. \
             Using `{actual}` (a typo, a stutter, or a personal pick) \
             makes every cross-project read cost an extra look-up: \
             readers see `{actual}.array` and have to confirm it is \
             really NumPy. Sticking to the canonical alias removes \
             that friction."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename the alias on the import line — \
             `import {module} as {expected}` — and update every \
             reference in the file. Most editors do this with one \
             rename refactor; ruff `ICN001` will autofix it."
        )),
        snippet,
        weight: 1,
    })
}
