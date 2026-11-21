//! `cc.iac.compose_default_network` — `docker-compose.yml` without an
//! explicit `networks:` block.
//!
//! Compose creates a default bridge network when none is declared.
//! Every service on the default network can reach every other service,
//! which makes lateral-movement testing harder and accidentally exposes
//! debug containers (adminer, redis-commander) to the app. Severity nit.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_compose_path, is_iac_test_fixture, location_for_file, IacFindingBlueprint,
};

/// Family-29 probe R-IAC-COMPOSE-DEFAULT-NETWORK.
#[derive(Debug, Default, Clone, Copy)]
pub struct ComposeDefaultNetworkRule;

impl Rule for ComposeDefaultNetworkRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.compose_default_network"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "docker-compose file relies on the default permissive network"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_compose_path(&path) || is_iac_test_fixture(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if has_explicit_networks(text) {
                continue;
            }
            out.push(emit(&path));
        }
        out
    }
}

/// True iff a top-level `networks:` block is declared (the YAML key
/// appears at column 1 — substring catches the common shape).
fn has_explicit_networks(text: &str) -> bool {
    text.lines().any(|l| {
        let trimmed_end = l.trim_end();
        trimmed_end == "networks:" || trimmed_end.starts_with("networks:") && !l.starts_with(' ')
    })
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.compose_default_network",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!(
            "Compose file `{}` has no explicit `networks:` block",
            path.as_str()
        ),
        explanation: format!(
            "`{}` declares services without an explicit `networks:` \
             topology. Compose puts every service on a single default \
             bridge — every container can reach every other container \
             on every port. Debug images (adminer, redis-commander, \
             phpMyAdmin) frequently ship as siblings of the app and \
             then accidentally expose internal databases.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Declare `networks: { backend: {}, frontend: {} }` and \
             attach each service only to the networks it actually needs. \
             Pair with `internal: true` on the database network so \
             nothing in the stack can dial out from it."
                .into(),
        ),
        snippet: format!("{} :: missing networks: block", path.as_str()),
        weight: 1,
    })
}
