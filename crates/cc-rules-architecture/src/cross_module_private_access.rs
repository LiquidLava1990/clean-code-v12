//! `cc.arch.cross_module_private_access` — Python `from foo._private
//! import X`.
//!
//! Python's leading-underscore convention marks a name as
//! module-private. Importing a single-underscore-prefixed name from
//! another module breaks that contract: the importing module is now
//! coupled to internals the owner is free to rename or delete without
//! any deprecation cycle.
//!
//! Detection target — Python `Import` nodes whose target string contains
//! a path component starting with a single underscore (but not double:
//! `__init__` is the public package marker, `__main__` is the entry
//! point, dunder names are conventionally public-via-protocol).
//!
//! OSS source: pylint W0212 (`protected-access`), Sonar S2384,
//! Semgrep `python.lang.maintainability.private-import`, ruff PLW0212
//! (proposed).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, target_module_for_import,
    ArchitectureFindingBlueprint,
};

/// Family-20 probe `cc.arch.cross_module_private_access`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CrossModulePrivateAccessRule;

impl Rule for CrossModulePrivateAccessRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.cross_module_private_access"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "import reaches into a single-underscore-prefixed (module-private) name in another module"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Import) {
            if let Some(finding) = check_import(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_import(ctx: &RuleContext<'_>, import_id: NodeId) -> Option<Finding> {
    let target = target_module_for_import(ctx.batch, import_id)?;
    let private_segment = first_private_segment(&target)?;
    let path = enclosing_file_path(ctx.batch, import_id)?;
    if !is_python_path(&path) {
        return None;
    }
    Some(emit_finding(
        ctx,
        import_id,
        &path,
        &target,
        &private_segment,
    ))
}

fn is_python_path(path: &camino::Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| ext == "py" || ext == "pyi")
}

/// Return the first path component of `target` that starts with a
/// single underscore but not a double. Returns `None` if no such
/// component exists. Splits on both `.` (Python module path) and `/`
/// (filesystem path representation some frontends emit).
fn first_private_segment(target: &str) -> Option<String> {
    for separator in ['.', '/'] {
        if let Some(seg) = target.split(separator).find(|s| is_private_segment(s)) {
            return Some(seg.to_owned());
        }
    }
    None
}

fn is_private_segment(seg: &str) -> bool {
    seg.starts_with('_') && !seg.starts_with("__") && seg.len() > 1
}

fn emit_finding(
    ctx: &RuleContext<'_>,
    import_id: NodeId,
    path: &camino::Utf8PathBuf,
    target: &str,
    private_segment: &str,
) -> Finding {
    let location = location_from_node(ctx.batch, import_id, path.clone());
    build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.cross_module_private_access",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        related: Vec::new(),
        headline: format!("import reaches into private segment `{private_segment}` of `{target}`"),
        explanation: "Python's single-underscore prefix marks a name as \
             module-private. Importing such a name from another module \
             couples the importer to internals the owner is free to \
             rename or delete without deprecation. The next refactor of \
             the owning module will silently break this importer at \
             runtime."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Either promote the symbol to the module's public surface \
             (drop the leading underscore + add it to `__all__`) or, if \
             the symbol is genuinely internal, copy the small piece you \
             need into the importer rather than reaching across the \
             encapsulation boundary."
                .into(),
        ),
        snippet: format!("from {target} import ..."),
        weight: 4,
    })
}
