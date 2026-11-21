//! `cc.supplychain.npm_dangerous_install_script` — `package.json`
//! ships a `preinstall` / `postinstall` / `install` hook.
//!
//! Heuristic: walk every [`NodeKind::File`] whose basename is
//! `package.json`. Scan source bytes for the three lifecycle script
//! keys. npm install scripts run with the user's full privileges on
//! every install; the supply-chain attack history (e.g. `event-stream`,
//! `ua-parser-js`) is dominated by malicious post-install hooks.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, location_for_file, SupplyChainFindingBlueprint};

/// Family-32 probe R-SUPPLYCHAIN-NPM-DANGEROUS-INSTALL-SCRIPT.
#[derive(Debug, Default, Clone, Copy)]
pub struct NpmDangerousInstallScriptRule;

const INSTALL_SCRIPT_KEYS: &[&str] = &["\"preinstall\"", "\"postinstall\"", "\"install\""];

impl Rule for NpmDangerousInstallScriptRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.npm_dangerous_install_script"
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
        "package.json declares preinstall/postinstall/install lifecycle script"
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
    if path.file_name() != Some("package.json") {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if let Some(key) = matched_install_key(line) {
            let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
            out.push(emit(&path, line_no, line.trim(), key));
        }
    }
}

fn matched_install_key(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    INSTALL_SCRIPT_KEYS
        .iter()
        .find(|k| trimmed.starts_with(*k))
        .copied()
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str, key: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.npm_dangerous_install_script",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`package.json` declares lifecycle script {} (RCE on every install)",
            key
        ),
        explanation: format!(
            "`{}` line {line_no} declares a {key} lifecycle script. npm \
             runs that script with the installing user's full privileges \
             on every `npm install` — every CI run, every developer \
             machine. The dominant supply-chain compromises of the past \
             decade (event-stream, ua-parser-js, coa, rc) all rode \
             post-install hooks. If the script is genuinely needed, \
             document why; otherwise remove it.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the lifecycle hook with a normal `scripts.build` / \
             `scripts.prepare` invoked deliberately. If native compilation \
             is unavoidable, ship prebuilt binaries via `node-pre-gyp` / \
             `prebuild-install` so the install path stays inert."
                .into(),
        ),
        snippet: line.to_owned(),
        weight: 4,
    })
}
