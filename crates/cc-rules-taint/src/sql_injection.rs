//! `cc.taint.sql_injection` — tainted value reaches a string-formatted
//! SQL query API.
//!
//! Sink table:
//!
//! - **Python**: `cursor.execute`, `connection.execute`, `db.execute`,
//!   `db.query`, `session.execute`.
//! - **Rust**: `sqlx::query`, `sqlx::query_as`, `diesel::sql_query`.
//! - **Go**: `db.Exec`, `db.Query`, `db.QueryRow`.
//! - **JavaScript**: `db.query`, `connection.query`, `client.query`.
//!
//! Phase-3 heuristic: the call's argument subtree contains a tainted
//! Identifier name AND no parameterized-query helper appears in the
//! same Function (sanitizers are stripped during taint-set construction).
//!
//! Parameterized-query suppression: when the FIRST argument to the sink
//! is a string Literal AND the call carries 2+ args, the call is the
//! canonical parameterized shape — `cursor.execute(SQL_STR, params)`
//! / `db.Exec(SQL, args...)` — and the tainted values flow as bound
//! parameters, not concatenated SQL. We suppress the finding rather
//! than report a false positive.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Severity};
use cc_frontend::query::{ast_children, node_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{run_taint_rule, SinkArgCheck, TaintRuleSpec, SOURCES_ANY};

const SINKS: &[&str] = &[
    "cursor.execute",
    "cursor.executemany",
    "connection.execute",
    "conn.execute",
    "db.execute",
    "db.query",
    "session.execute",
    "sqlx::query",
    "sqlx::query_as",
    "sqlx::query_scalar",
    "diesel::sql_query",
    "db.Exec",
    "db.Query",
    "db.QueryRow",
    "client.query",
];

/// Family-4 probe `cc.taint.sql_injection`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.sql_injection"
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
        "tainted value reaches a string-formatted SQL query"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        run_taint_rule(
            ctx,
            &TaintRuleSpec {
                rule_id: "cc.taint.sql_injection",
                sources: SOURCES_ANY,
                sinks: SINKS,
                confidence: 0.98,
                weight: 8,
                message: build_message,
                remediation: "Switch to a parameterized API (e.g. \
                              `cursor.execute(sql, params)`, \
                              `sqlx::query(...).bind(...)`, \
                              `db.PrepareContext`). Never concatenate \
                              or interpolate untrusted values into a \
                              SQL string.",
                sink_arg_check: Some(reject_parameterized_form as SinkArgCheck),
                seed_parameters: true,
            },
        )
    }
}

/// True iff this sink call should fire — i.e. it is NOT the canonical
/// parameterized form `cursor.execute(SQL_LITERAL, params)`.
///
/// The parameterized form is recognised structurally:
/// - the first positional argument to the call is a string-kind
///   [`NodeKind::Literal`], AND
/// - the call carries at least one additional argument (the params
///   tuple / sequence).
///
/// Under that pattern, the tainted identifiers reach the call only as
/// bound parameters, never as raw SQL — every supported sink in the
/// table treats arg-0 as literal SQL and the rest as bind values.
fn reject_parameterized_form(
    batch: &cc_cpg::CpgWriteBatch,
    _source: &dyn cc_rules::SourceTable,
    _path: &camino::Utf8PathBuf,
    call: NodeId,
    _callee: &str,
) -> bool {
    let args = ordered_call_args(batch, call);
    let Some(first) = args.first() else {
        return true;
    };
    if args.len() < 2 {
        return true;
    }
    if !is_string_literal(batch, *first) {
        return true;
    }
    false
}

fn ordered_call_args(batch: &cc_cpg::CpgWriteBatch, call: NodeId) -> Vec<NodeId> {
    ast_children(batch, call).collect()
}

fn is_string_literal(batch: &cc_cpg::CpgWriteBatch, id: NodeId) -> bool {
    if node_kind(batch, id) != Some(NodeKind::Literal) {
        return false;
    }
    match string_prop(batch, id, "literal_kind") {
        Some(kind) => matches!(kind, "string" | "str" | "String"),
        // Frontend may not stamp literal_kind for every language — fall
        // back to "any literal head accepted" since a non-string literal
        // (int, bool) as arg-0 of an SQL sink is non-sensical anyway.
        None => true,
    }
}

fn build_message(callee: &str) -> (String, String) {
    let head = format!("untrusted input flows into SQL sink `{callee}` without parameterization");
    let body = format!(
        "A value originating from request data, environment, or CLI input \
         reaches `{callee}`. Concatenated SQL is the canonical injection \
         vector — even a single tainted segment compromises the query."
    );
    (head, body)
}
