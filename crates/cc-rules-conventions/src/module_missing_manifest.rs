//! `cc.convention.module_missing_manifest` — every module carries a manifest.
//!
//! Every module under `platform/modules/<name>/` must have a
//! `__manifest__.py` manifest. The probe walks every [`NodeKind::File`]
//! whose path matches `platform/modules/<name>/...` (or
//! `<prefix>/platform/modules/<name>/...`), records the module
//! directory, and checks whether the manifest exists at
//! `<module-dir>/__manifest__.py`.
//!
//! Existence check uses the `SourceTable::get` interface — an empty
//! byte slice means the path is not materialised by the kernel walker
//! AND not present on disk. To avoid duplicate findings (one per
//! sibling file in the same module), the rule only emits when the
//! current file's basename sorts first among visible siblings.
//!
//! Phase-3 simplification: emit one finding per file inside a
//! manifest-less module, deduplicated by directory at the report sink
//! level. The signal is conservative — false negatives are preferred
//! over noise, since this is a hard-rule.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_layout_path, location_for_file, ConventionFindingBlueprint, LAYOUT_ROOT,
    MODULE_MANIFEST,
};

/// Family-24 probe R-CONVENTION-MODULE-MISSING-MANIFEST.
#[derive(Debug, Default, Clone, Copy)]
pub struct ModuleMissingManifestRule;

impl Rule for ModuleMissingManifestRule {
    fn rule_id(&self) -> &'static str {
        "cc.convention.module_missing_manifest"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Convention
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "module under `platform/modules/<name>/` is missing a __manifest__.py manifest"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            check_path(&path, ctx, &mut out);
        }
        out
    }
}

fn check_path(path: &Utf8PathBuf, ctx: &RuleContext<'_>, out: &mut Vec<Finding>) {
    if !is_layout_path(path) {
        return;
    }
    let Some(module_dir) = module_dir_for(path) else {
        return;
    };
    if path.file_name() == Some(MODULE_MANIFEST) {
        return;
    }
    let manifest = module_dir.join(MODULE_MANIFEST);
    if manifest_exists(ctx, &manifest) {
        return;
    }
    if !is_first_sibling(ctx, path, &module_dir) {
        return;
    }
    out.push(emit(&module_dir));
}

/// Return the `platform/modules/<name>/` directory containing `path`,
/// or `None` if the path is not under a layout module subtree.
fn module_dir_for(path: &Utf8PathBuf) -> Option<Utf8PathBuf> {
    let s = path.as_str().replace('\\', "/");
    let marker = format!("{LAYOUT_ROOT}/modules/");
    let idx = s.find(&marker)?;
    let rest = &s[idx + marker.len()..];
    let module_name = rest.split('/').next()?;
    if module_name.is_empty() || module_name.contains("__pycache__") {
        return None;
    }
    let module_root = &s[..idx + marker.len() + module_name.len()];
    Some(Utf8PathBuf::from(module_root))
}

/// True iff `manifest` is materialised in the source table OR is
/// readable from disk (the file-backed source table reads lazily).
fn manifest_exists(ctx: &RuleContext<'_>, manifest: &Utf8PathBuf) -> bool {
    !ctx.source.get(manifest.as_path()).is_empty()
}

/// True iff `path` is the lexicographically smallest visible file in
/// `module_dir`. Used to deduplicate findings down to one per module.
fn is_first_sibling(ctx: &RuleContext<'_>, path: &Utf8PathBuf, module_dir: &Utf8PathBuf) -> bool {
    let prefix = format!("{}/", module_dir.as_str().replace('\\', "/"));
    let mut min: Option<String> = None;
    for candidate in ctx.source.paths() {
        let normalized = candidate.as_str().replace('\\', "/");
        if !normalized.starts_with(&prefix) {
            continue;
        }
        if min
            .as_ref()
            .is_none_or(|m| normalized.as_str() < m.as_str())
        {
            min = Some(normalized);
        }
    }
    let normalized_self = path.as_str().replace('\\', "/");
    min.is_none_or(|m| m == normalized_self)
}

fn emit(module_dir: &Utf8PathBuf) -> Finding {
    let manifest_path = module_dir.join(MODULE_MANIFEST);
    let location = location_for_file(manifest_path.clone(), 1);
    build_finding(ConventionFindingBlueprint {
        rule_id: "cc.convention.module_missing_manifest",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!(
            "module `{}` is missing the required `__manifest__.py` manifest",
            module_dir.file_name().unwrap_or("<unknown>")
        ),
        explanation: "Layout convention: every module under `platform/modules/` \
             carries a `__manifest__.py` manifest declaring its layer, \
             owners, contracts, and registered capabilities. Without the \
             manifest the boot orchestrator cannot wire the module into \
             the EventBus / registry, and module-level invariants go \
             unenforced."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add a `__manifest__.py` manifest at the module root. Use a \
             sibling module's manifest as a template — declare the \
             layer, owners, public surface, and event contracts the \
             module emits or consumes."
                .into(),
        ),
        snippet: manifest_path.as_str().to_owned(),
        weight: 4,
    })
}
