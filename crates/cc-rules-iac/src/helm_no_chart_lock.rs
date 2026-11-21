//! `cc.iac.helm_no_chart_lock` — Helm `Chart.yaml` without adjacent `Chart.lock`.
//!
//! Mirrors the design of `cc.ci.lockfile_uncommitted` for Helm: a chart
//! whose dependencies are not locked (no `Chart.lock` next to
//! `Chart.yaml`) lets transitive sub-charts float between every render.

use std::collections::BTreeSet;

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_helm_chart_lock, is_helm_chart_yaml, is_iac_test_fixture, location_for_file,
    IacFindingBlueprint,
};

/// Family-29 probe R-IAC-HELM-NO-CHART-LOCK.
#[derive(Debug, Default, Clone, Copy)]
pub struct HelmNoChartLockRule;

impl Rule for HelmNoChartLockRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.helm_no_chart_lock"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Helm chart present (`Chart.yaml`) but no companion `Chart.lock`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let paths: Vec<Utf8PathBuf> = nodes_of_kind(ctx.batch, NodeKind::File)
            .filter_map(|node| string_prop(ctx.batch, node.id, "path").map(Utf8PathBuf::from))
            .filter(|p| !is_iac_test_fixture(p))
            .collect();
        let lock_dirs = collect_lock_dirs(&paths);
        paths
            .iter()
            .filter(|p| is_helm_chart_yaml(p))
            .filter(|p| !lock_dir_present(p, &lock_dirs))
            .map(|p| emit(p))
            .collect()
    }
}

/// Collect the set of parent directories that contain a `Chart.lock`.
fn collect_lock_dirs(paths: &[Utf8PathBuf]) -> BTreeSet<Utf8PathBuf> {
    paths
        .iter()
        .filter(|p| is_helm_chart_lock(p))
        .filter_map(|p| p.parent().map(Utf8PathBuf::from))
        .collect()
}

/// True iff `chart_yaml`'s parent directory is in the lock-dir set.
fn lock_dir_present(chart_yaml: &Utf8PathBuf, lock_dirs: &BTreeSet<Utf8PathBuf>) -> bool {
    chart_yaml
        .parent()
        .is_some_and(|parent| lock_dirs.contains(&Utf8PathBuf::from(parent)))
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(IacFindingBlueprint {
        rule_id: "cc.iac.helm_no_chart_lock",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "Helm chart `{}` has no committed `Chart.lock`",
            path.as_str()
        ),
        explanation: format!(
            "Chart at `{}` declares dependencies (or could) but has no \
             `Chart.lock` committed alongside. Sub-chart versions float \
             between every `helm dependency update` run, so two engineers \
             rendering the same chart can ship subtly different manifests \
             — security audits become impossible to anchor.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Run `helm dependency update` and commit the resulting \
             `Chart.lock` next to `Chart.yaml`. Wire `helm dependency \
             build --check` (or a CI step that fails on unlocked \
             charts) into the release pipeline."
                .into(),
        ),
        snippet: path.as_str().to_owned(),
        weight: 3,
    })
}
