//! `cc.supplychain.cargo_unpinned_git_dep` — `Cargo.toml` git dep
//! without an explicit `rev`.
//!
//! Heuristic: walk every [`NodeKind::File`] whose basename is
//! `Cargo.toml`. Scan source bytes line-by-line for `git = "..."`
//! declarations, then confirm the same dependency table also pins a
//! `rev = "<hash>"`. A `git`/`branch` dependency is mutable: the
//! upstream repo can rewrite history and `cargo update` silently picks
//! up the new HEAD on the next solve.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, location_for_file, SupplyChainFindingBlueprint};

/// Family-32 probe R-SUPPLYCHAIN-CARGO-UNPINNED-GIT-DEP.
#[derive(Debug, Default, Clone, Copy)]
pub struct CargoUnpinnedGitDepRule;

impl Rule for CargoUnpinnedGitDepRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.cargo_unpinned_git_dep"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Cargo.toml git dependency without `rev = \"<hash>\"`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(raw) = string_prop(ctx.batch, file_id, "path") else {
        return;
    };
    let path = Utf8PathBuf::from(raw);
    if path.file_name() != Some("Cargo.toml") {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for finding in unpinned_git_lines(&path, text) {
        out.push(finding);
    }
}

/// Find every line that declares `git = "..."` whose neighbouring
/// inline-table or section does not also pin `rev = "..."`.
fn unpinned_git_lines(path: &Utf8PathBuf, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.contains("git =") && !trimmed.contains("git=") {
            continue;
        }
        // Inline-table form: foo = { git = "...", branch = "main" }
        // (single line — `rev` either present or not on the same line).
        if trimmed.starts_with('#') {
            continue;
        }
        if line_has_rev_pin(line) {
            continue;
        }
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        out.push(emit(path, line_no, trimmed));
    }
    out
}

/// True iff the line pins `rev = "<value>"` (any non-empty value).
fn line_has_rev_pin(line: &str) -> bool {
    let needle = "rev";
    let bytes = line.as_bytes();
    let start = match line.find(needle) {
        Some(s) => s,
        None => return false,
    };
    let after = &bytes[start + needle.len()..];
    // Skip whitespace and an `=` to confirm this is `rev =` not `revision`.
    let mut i = 0;
    while i < after.len() && after[i].is_ascii_whitespace() {
        i += 1;
    }
    after.get(i) == Some(&b'=')
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.cargo_unpinned_git_dep",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "Cargo.toml git dependency lacks `rev = \"<hash>\"`".into(),
        explanation: format!(
            "`{}` line {line_no} declares a git dependency without an \
             explicit `rev`. The dependency floats on whatever HEAD the \
             upstream repo has on the next `cargo update` — and upstream \
             can force-push history or land malicious code without any \
             local diff to your manifest. `branch = \"main\"` is *not* a \
             pin.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add `rev = \"<40-char-sha>\"` next to `git = \"...\"` (the \
             commit you have audited). Bump the rev deliberately when \
             you've reviewed upstream changes — the same discipline you \
             apply to GitHub Actions pinning."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 3,
    })
}
