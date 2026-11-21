//! Internal helpers shared across Family-24 (layout-convention) probes.
//!
//! The pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-secrets`, `cc-rules-perf`, `cc-rules-bugs`, and
//! `cc-rules-concurrency` by re-implementing the small set of
//! traversal primitives every convention probe needs.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_children, ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinConventionsPack;

/// Probe-pack identity stamped on every Family-24 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinConventionsPack::PACK_ID,
        BuiltinConventionsPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "path").map(Utf8PathBuf::from);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property,
/// falling back to start-of-file when the property is missing.
pub(crate) fn location_from_node(batch: &CpgWriteBatch, id: NodeId, file: Utf8PathBuf) -> Location {
    let (start, end) = range_prop(batch, id, "range").map_or_else(
        || {
            let zero = Position::new(1, 1, 0);
            (zero, zero)
        },
        |r| {
            (
                Position::new(r.start.line, r.start.column, r.start.offset),
                Position::new(r.end.line, r.end.column, r.end.offset),
            )
        },
    );
    Location {
        file,
        start,
        end,
        node_id: Some(cc_finding::NodeId::new(id.get().to_string())),
        function_qualified_name: string_prop(batch, id, "name").map(str::to_owned),
    }
}

/// Build a file-scoped [`Location`] (line 1, column 1) for a path.
pub(crate) fn location_for_file(file: Utf8PathBuf, line: u32) -> Location {
    let pos = Position::new(line.max(1), 1, 0);
    Location {
        file,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    }
}

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] — every pack
/// uses the same canonical merge logic so substring needles see a
/// uniform haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
}

/// Best-effort first-argument string-literal text for a Call node.
///
/// Returns the literal value when the first argument is a string
/// literal (`first_arg_value`) — does NOT return identifier names,
/// because the untyped-event rule cares specifically about
/// string-literal event names.
#[must_use]
pub(crate) fn first_arg_literal(batch: &CpgWriteBatch, id: NodeId) -> Option<String> {
    string_prop(batch, id, "first_arg_value").map(str::to_owned)
}

/// Best-effort first-argument text (literal value OR identifier name).
///
/// Used for path-style argument matching where either form is OK.
#[must_use]
pub(crate) fn first_arg_text(batch: &CpgWriteBatch, id: NodeId) -> Option<String> {
    for key in ["first_arg_value", "first_arg_name", "first_arg"] {
        if let Some(v) = string_prop(batch, id, key) {
            return Some(v.to_owned());
        }
    }
    None
}

/// Collect every descendant [`NodeKind::Call`] under `root` in
/// source-order. Caller supplies an empty buffer; helper fills + sorts.
pub(crate) fn collect_descendant_calls(batch: &CpgWriteBatch, root: NodeId, out: &mut Vec<NodeId>) {
    let mut stack: Vec<NodeId> = ast_children(batch, root).collect();
    while let Some(id) = stack.pop() {
        for child in ast_children(batch, id) {
            stack.push(child);
        }
        if node_kind(batch, id) == Some(NodeKind::Call) {
            out.push(id);
        }
    }
    out.sort_by_key(|id| range_prop(batch, *id, "range").map_or(0, |r| r.start.offset));
}

/// Root directory of the modular service layout this pack enforces.
pub(crate) const LAYOUT_ROOT: &str = "platform";

/// Per-module manifest file every `platform/modules/<name>/` carries.
pub(crate) const MODULE_MANIFEST: &str = "__manifest__.py";

/// True iff `path` lives inside a `platform/` layout tree.
///
/// Matches `platform/...` at the repo root and nested
/// `<prefix>/platform/...` trees. Files outside this boundary are
/// skipped by every Family-24 probe so codebases that do not use the
/// layout see zero false positives.
#[must_use]
pub(crate) fn is_layout_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let root = format!("{LAYOUT_ROOT}/");
    s.starts_with(&root) || s.contains(&format!("/{root}"))
}

/// True iff `arg` looks like a write into the shared `data/...` tree.
#[must_use]
pub(crate) fn is_protected_data_path(arg: &str) -> bool {
    let normalized = arg.replace('\\', "/");
    normalized.starts_with("data/")
        || normalized.starts_with("./data/")
        || normalized.contains("/data/")
}

/// Inputs every Family-24 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct ConventionFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.convention.startup_py_exists"`.
    pub rule_id: &'static str,
    /// Severity stamped on the finding.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the issue manifests.
    pub location: Location,
    /// One-line headline shown first in any sink.
    pub headline: String,
    /// Multi-line explanation covering what + why.
    pub explanation: String,
    /// Concrete remediation guidance the user can act on.
    pub remediation: Remediation,
    /// Source-code snippet anchoring the finding (may be empty).
    pub snippet: String,
    /// Blocking-debt weight for score impact.
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`ConventionFindingBlueprint`].
///
/// `R-ERR-ACTION`: builder failure means a required field is missing —
/// fix the call site, do not paper over with `unwrap_or_default`.
pub(crate) fn build_finding(blueprint: ConventionFindingBlueprint) -> Finding {
    let ConventionFindingBlueprint {
        rule_id,
        severity,
        confidence,
        location,
        headline,
        explanation,
        remediation,
        snippet,
        weight,
    } = blueprint;
    let evidence = Evidence::from_snippet(snippet);
    let message = ActionableMessage::new(headline, explanation, remediation);
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Convention)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-24 finding builder receives all required fields")
}
