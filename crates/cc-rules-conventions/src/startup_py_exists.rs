//! `cc.convention.startup_py_exists` — one boot path, no `startup.py`.
//!
//! The layout has exactly one boot path. The canonical entry point is
//! `platform/main.py` (root shim) + `boot/main.py` (orchestrator);
//! `startup.py` must not exist. The probe walks every
//! [`NodeKind::File`] inside a `platform/` tree and flags any whose basename is `startup.py`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_layout_path, location_for_file, ConventionFindingBlueprint,
};

/// Family-24 probe R-CONVENTION-STARTUP-PY-EXISTS.
#[derive(Debug, Default, Clone, Copy)]
pub struct StartupPyExistsRule;

impl Rule for StartupPyExistsRule {
    fn rule_id(&self) -> &'static str {
        "cc.convention.startup_py_exists"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Convention
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.99)
    }
    fn description(&self) -> &'static str {
        "`startup.py` is a second boot path — the entry point is `platform/main.py`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_layout_path(&path) {
                continue;
            }
            if path.file_name() != Some("startup.py") {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(ConventionFindingBlueprint {
        rule_id: "cc.convention.startup_py_exists",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.99),
        location,
        headline: "`startup.py` exists — the layout allows one boot path only".into(),
        explanation: "The layout pins ONE boot path: `platform/main.py` \
             (root shim) delegating to `boot/main.py` (orchestrator). \
             `startup.py` is a forbidden alternative entry point — its \
             presence creates two boot paths and bypasses the EventBus / \
             secret-store / config wiring."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Delete `startup.py`. If the file holds initialisation logic, \
             move it under `platform/boot/` and call it from `boot/main.py` \
             via the orchestrator. Update any docs / launchers that \
             referenced `startup.py`."
                .into(),
        ),
        snippet: path.as_str().to_owned(),
        weight: 8,
    })
}
