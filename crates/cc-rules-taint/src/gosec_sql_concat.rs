//! `cc.taint.gosec_sql_concat` — Go `db.Query("SELECT ... " + x)` /
//! `db.Exec(fmt.Sprintf("..."), ...)` style SQL composition.
//!
//! Mirrors [gosec G201] (`SQL query construction using format string`)
//! and [gosec G202] (`SQL query construction using string concatenation`).
//!
//! The existing [`crate::sql_injection`] probe catches AST-level
//! tainted-value flow into `db.Exec` / `db.Query`. This probe is the
//! syntactic Go-only fallback that fires whenever the *first* arg to
//! `db.Query` / `db.Exec` / `db.QueryRow` is a `+`-concatenation OR a
//! `fmt.Sprintf(...)` call — both shapes are unsafe regardless of
//! whether dataflow can prove a request taint.
//!
//! [gosec G201]: https://github.com/securego/gosec/blob/master/rules/sql.go

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::_go_syntax::{contains_unquoted_plus, first_arg_slice};
use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

const SINK_NEEDLES: &[&str] = &[
    "db.Query(",
    "db.Exec(",
    "db.QueryRow(",
    "db.QueryContext(",
    "db.ExecContext(",
    "db.QueryRowContext(",
    "tx.Query(",
    "tx.Exec(",
    "tx.QueryRow(",
];

/// Family-4 probe `cc.taint.gosec_sql_concat`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecSqlConcatRule;

impl Rule for GosecSqlConcatRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.gosec_sql_concat"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Go db.Query/Exec called with `+`-concat or fmt.Sprintf as first arg (gosec G201/G202)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_go_source(&path) {
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

fn is_go_source(path: &Utf8PathBuf) -> bool {
    let ext_ok = path.extension().map(str::to_ascii_lowercase).as_deref() == Some("go");
    if !ext_ok {
        return false;
    }
    !path
        .file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if let Some(needle) = matched_sink(line) {
            if first_arg_is_concat_or_sprintf(line, needle) {
                out.push(emit(path.clone(), idx + 1, line, needle));
            }
        }
    }
}

fn matched_sink(line: &str) -> Option<&'static str> {
    SINK_NEEDLES.iter().copied().find(|n| line.contains(n))
}

/// True iff the first argument to `<sink>(` looks like a `+`-concat
/// expression OR an `fmt.Sprintf(...)` call.
fn first_arg_is_concat_or_sprintf(line: &str, needle: &str) -> bool {
    let Some(open) = line.find(needle) else {
        return false;
    };
    let after = &line[open + needle.len()..];
    let arg = first_arg_slice(after);
    let trimmed = arg.trim();
    if trimmed.starts_with("fmt.Sprintf(") {
        return true;
    }
    contains_unquoted_plus(arg)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TaintFindingBlueprint {
        rule_id: "cc.taint.gosec_sql_concat",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`{}` called with concatenated / Sprintf'd SQL (gosec G201/G202)",
            needle.trim_end_matches('('),
        ),
        explanation: "The first argument to a `db.Query` / `db.Exec` / \
             `db.QueryRow` (or transaction sibling) is being assembled \
             by string concatenation or `fmt.Sprintf`. gosec G201 / G202 \
             flags this exact shape: any user-supplied segment becomes \
             part of the SQL grammar, which is the canonical injection \
             vector."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass the SQL as a constant string with `?` / `$N` \
             placeholders and bind values as additional arguments \
             (`db.Query(\"SELECT ... WHERE id = ?\", id)`). For dynamic \
             column / table names use a strict allow-list, never \
             concatenation."
                .into(),
        ),
        snippet,
        weight: 7,
    })
}
