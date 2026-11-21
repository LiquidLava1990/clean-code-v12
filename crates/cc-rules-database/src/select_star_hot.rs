//! `cc.db.select_star_hot` — `SELECT *` in source string literals.
//!
//! Heuristic: walk every [`NodeKind::File`], read the source bytes from
//! the [`cc_rules::SourceTable`], and case-insensitively look for
//! `SELECT *` (or `select *`) inside what looks like a string literal.
//! Skip test files entirely and skip rule-pack source files (the
//! detector pattern would self-flag).
//!
//! Phase-4 conservatism: a single occurrence anywhere in the file is
//! enough — locating the literal precisely awaits a Phase-5 SQL parser.
//! The line of the first hit is reported.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, location_for_file, DatabaseFindingBlueprint,
};

/// Family-10 probe R-DB-SELECT-STAR-HOT.
#[derive(Debug, Default, Clone, Copy)]
pub struct SelectStarHotRule;

const QUOTE_BYTES: &[u8] = b"\"'`";

impl Rule for SelectStarHotRule {
    fn rule_id(&self) -> &'static str {
        "cc.db.select_star_hot"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Db
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "`SELECT *` in a query string — fetches columns the caller never reads"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            if let Some(finding) = scan_file(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId) -> Option<Finding> {
    let raw = string_prop(ctx.batch, file_id, "path")?;
    let path = Utf8PathBuf::from(raw);
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).ok()?;
    let (line_no, line) = first_select_star_hit(text)?;
    Some(emit(&path, line_no, line.trim()))
}

/// Find the first line containing a `SELECT *` (case-insensitive)
/// followed by whitespace AND adjacent to a quote character (so
/// non-string mentions in comments are skipped).
fn first_select_star_hit(text: &str) -> Option<(u32, &str)> {
    for (idx, line) in text.lines().enumerate() {
        if !line_has_select_star(line) {
            continue;
        }
        if !line_has_quote(line) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        return Some((line_no, line));
    }
    None
}

fn line_has_select_star(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    let mut start = 0;
    while let Some(pos) = upper[start..].find("SELECT") {
        let abs = start + pos;
        let after = &upper[abs + "SELECT".len()..];
        let trimmed_after = after.trim_start();
        if trimmed_after.starts_with('*') {
            return true;
        }
        start = abs + "SELECT".len();
    }
    false
}

fn line_has_quote(line: &str) -> bool {
    line.bytes().any(|b| QUOTE_BYTES.contains(&b))
}

fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(DatabaseFindingBlueprint {
        rule_id: "cc.db.select_star_hot",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: "`SELECT *` in a query string".to_owned(),
        explanation: format!(
            "`{}` issues `SELECT *`. The query fetches every column on the \
             table — including ones the caller never reads, including new \
             columns added by future migrations. That bloats payloads, \
             defeats covering-index plans, and silently couples the caller \
             to schema drift. Always list the columns you actually need.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `SELECT *` with the explicit column list. If the call \
             site really wants every column, define a view or a typed \
             record so additions to the schema are reviewed instead of \
             implicitly fanning out."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 2,
    })
}
