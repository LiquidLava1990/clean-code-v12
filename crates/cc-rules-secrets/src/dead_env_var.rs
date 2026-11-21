//! `cc.config.dead_env_var` — flag environment variables that are
//! looked up but whose name appears nowhere else in the same batch.
//!
//! Phase-2 simplification: we walk every call to a known env-var
//! accessor (`os.environ.get`, `os.getenv`, `process.env.X`,
//! `std::env::var`, `os.LookupEnv`) and extract the name argument. The
//! rule fires when the same name does not appear anywhere else in the
//! batch's source bytes. This is heuristic-grade — a future Phase-3
//! version should consult the project fingerprint for cross-batch
//! reachability.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, SecretsFindingBlueprint,
};

/// Family-19 probe R-DEAD-ENV.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadEnvVarRule;

impl Rule for DeadEnvVarRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.dead_env_var"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "environment variable is read but its name appears nowhere else"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "callee_ref")?;
    if !is_env_accessor(callee) {
        return None;
    }
    let var_name = extract_var_name(ctx, id)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if name_appears_elsewhere(ctx, &path, &var_name, id) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.dead_env_var",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("env var `{var_name}` is read but never referenced elsewhere"),
        explanation: format!(
            "The codebase reads `{var_name}` via {callee} but no other source line \
             in this batch mentions it. Either the variable name is a typo (the \
             intended name lives in `.env` or your deploy config), the read is \
             dead, or the value is consumed only via this single read with no \
             corresponding fallback."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Verify the env-var name matches your deploy config + `.env.example`. \
             If the read truly has no consumer, delete it; if cross-file usage \
             exists, the Phase-3 fingerprint extension will surface it — pin the \
             rule off via config until then."
                .into(),
        ),
        snippet: format!("{callee}(\"{var_name}\")"),
        weight: 1,
    }))
}

fn is_env_accessor(callee: &str) -> bool {
    matches!(
        callee,
        "os.environ.get"
            | "os.getenv"
            | "std::env::var"
            | "std::env::var_os"
            | "process.env"
            | "os.LookupEnv"
            | "os.Getenv"
    ) || callee.starts_with("process.env.")
}

fn extract_var_name(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    if let Some(name) = string_prop(ctx.batch, id, "first_arg_value") {
        return Some(name.to_owned());
    }
    let callee = string_prop(ctx.batch, id, "callee_ref")?;
    callee.strip_prefix("process.env.").map(str::to_owned)
}

fn name_appears_elsewhere(
    ctx: &RuleContext<'_>,
    path: &Utf8PathBuf,
    name: &str,
    call_id: NodeId,
) -> bool {
    if name.len() < 3 {
        return true;
    }
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let occurrences = text.matches(name).count();
    if occurrences > 1 {
        return true;
    }
    let _ = call_id;
    false
}
