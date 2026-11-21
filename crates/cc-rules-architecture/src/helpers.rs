//! Internal helpers shared across Family-20 (architecture) probes.
//!
//! Re-implements the small set of traversal primitives this pack needs
//! plus a per-batch [`ImportGraph`] + [`kahn_cycle_members`] cycle
//! detector. The fingerprint crate ships a similar `LayerGraph` for
//! repo-wide use; rules build a per-batch graph here so they stay
//! correct even when `RuleContext::project` carries the empty
//! placeholder fingerprint.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinArchitecturePack;

/// Probe-pack identity stamped on every Family-20 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinArchitecturePack::PACK_ID,
        BuiltinArchitecturePack::PACK_SEMVER,
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

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its [`NodeId`]. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_file_id(batch: &CpgWriteBatch, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return Some(id);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property, falling
/// back to the start of the file when the property is missing.
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

/// Resolve the source-module name for the batch — the module *doing*
/// the importing. Preference: the [`NodeKind::Module`] node's
/// `qualified_name` → `name` → the [`NodeKind::File`] node's `path`
/// stripped of suffix. Returns `None` when no anchor is available.
#[must_use]
pub(crate) fn source_module_name(batch: &CpgWriteBatch) -> Option<String> {
    for node in batch.nodes() {
        if node.kind != NodeKind::Module {
            continue;
        }
        if let Some(s) = string_prop(batch, node.id, "qualified_name") {
            return Some(s.to_owned());
        }
        if let Some(s) = string_prop(batch, node.id, "name") {
            return Some(s.to_owned());
        }
    }
    file_path_as_module(batch)
}

/// Fall back to the file path as the source-module identifier when no
/// `Module` node is present (Rust files routinely have only a `File`).
fn file_path_as_module(batch: &CpgWriteBatch) -> Option<String> {
    for node in batch.nodes() {
        if node.kind == NodeKind::File {
            if let Some(path) = string_prop(batch, node.id, "path") {
                return Some(strip_extension(path));
            }
        }
    }
    None
}

fn strip_extension(path: &str) -> String {
    let normalised = path.replace('\\', "/");
    match normalised.rsplit_once('.') {
        Some((stem, _ext)) => stem.to_owned(),
        None => normalised,
    }
}

/// Resolve the target-module identifier an [`NodeKind::Import`] points
/// at. Order: schema-canonical `target_module` → `source` (Rust /
/// Python alias) → `path` (TS / Go) → `name`. Returns `None` for an
/// Import the frontend was unable to resolve — those are handled
/// conservatively (no finding) by every rule in this pack.
#[must_use]
pub(crate) fn target_module_for_import(batch: &CpgWriteBatch, import_id: NodeId) -> Option<String> {
    for key in ["target_module", "source", "path", "name"] {
        if let Some(s) = string_prop(batch, import_id, key) {
            if !s.is_empty() {
                return Some(s.to_owned());
            }
        }
    }
    None
}

/// Inputs every Family-20 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct ArchitectureFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.arch.layer_violation"`.
    pub rule_id: &'static str,
    /// Severity to stamp on the finding.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the issue manifests.
    pub location: Location,
    /// Secondary locations — partner cycle members, etc. Empty by default.
    pub related: Vec<cc_finding::RelatedLocation>,
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

/// Build a complete [`Finding`] from an [`ArchitectureFindingBlueprint`].
pub(crate) fn build_finding(blueprint: ArchitectureFindingBlueprint) -> Finding {
    let ArchitectureFindingBlueprint {
        rule_id,
        severity,
        confidence,
        location,
        related,
        headline,
        explanation,
        remediation,
        snippet,
        weight,
    } = blueprint;
    let evidence = Evidence::from_snippet(snippet);
    let message = ActionableMessage::new(headline, explanation, remediation);
    let mut builder = FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Arch)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version());
    for r in related {
        builder = builder.related(r);
    }
    builder
        .build()
        .expect("Family-20 finding builder receives all required fields")
}

/// Per-batch import graph keyed on module name.
///
/// Built by walking every [`NodeKind::Import`] in a batch and recording
/// `source_module → target_module`. Rules use it for layer violation
/// detection, fan-in / fan-out tallies, and cycle detection.
#[derive(Debug, Default, Clone)]
pub(crate) struct ImportGraph {
    edges: BTreeMap<String, BTreeSet<String>>,
    incoming: BTreeMap<String, BTreeSet<String>>,
}

impl ImportGraph {
    /// Empty graph.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record an import edge `from → to`. Self-imports are dropped.
    pub(crate) fn record(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        self.edges
            .entry(from.to_owned())
            .or_default()
            .insert(to.to_owned());
        self.incoming
            .entry(to.to_owned())
            .or_default()
            .insert(from.to_owned());
    }

    /// Outgoing-edge count for `module` — how many other modules it imports.
    #[must_use]
    pub(crate) fn fan_out(&self, module: &str) -> usize {
        self.edges.get(module).map_or(0, BTreeSet::len)
    }

    /// Incoming-edge count for `module` — how many other modules import it.
    #[must_use]
    pub(crate) fn fan_in(&self, module: &str) -> usize {
        self.incoming.get(module).map_or(0, BTreeSet::len)
    }

    /// True iff `from` may import `to` under the downward-only doctrine.
    /// Mirrors `cc_fingerprint::LayerGraph::is_downward_only`: an import
    /// is forbidden when `to` already reaches back to `from` in the
    /// recorded graph (i.e. it would close a cycle).
    #[must_use]
    pub(crate) fn is_downward_only(&self, from: &str, to: &str) -> bool {
        if from == to {
            return false;
        }
        !self.reaches(to, from)
    }

    /// Bounded BFS. Bound is the total edge count to guarantee
    /// termination even on malformed graphs.
    fn reaches(&self, start: &str, target: &str) -> bool {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut frontier: Vec<String> = vec![start.to_owned()];
        let bound = self.total_edges() + 1;
        let mut steps = 0usize;
        while let Some(node) = frontier.pop() {
            steps += 1;
            if steps > bound {
                return false;
            }
            if !visited.insert(node.clone()) {
                continue;
            }
            let Some(targets) = self.edges.get(&node) else {
                continue;
            };
            for next in targets {
                if next == target {
                    return true;
                }
                if !visited.contains(next) {
                    frontier.push(next.clone());
                }
            }
        }
        false
    }

    fn total_edges(&self) -> usize {
        self.edges.values().map(BTreeSet::len).sum()
    }

    /// Borrow the outgoing-edge map (read-only).
    pub(crate) const fn edges(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.edges
    }
}

/// Build an [`ImportGraph`] over a single [`CpgWriteBatch`].
///
/// One Module's perspective per batch — the lifted file *is* the
/// importer. We resolve its source-module once, then walk every Import
/// node and resolve the target-module from import props.
#[must_use]
pub(crate) fn build_import_graph(batch: &CpgWriteBatch) -> ImportGraph {
    let mut graph = ImportGraph::new();
    let Some(source) = source_module_name(batch) else {
        return graph;
    };
    for node in batch.nodes() {
        if node.kind != NodeKind::Import {
            continue;
        }
        if let Some(target) = target_module_for_import(batch, node.id) {
            graph.record(&source, &target);
        }
    }
    graph
}

/// Run Kahn's algorithm and return every module that participates in
/// at least one cycle.
///
/// Algorithm: repeatedly remove every node with in-degree zero from
/// the working copy. Anything left over once no zero-in-degree nodes
/// remain is in a cycle. Output is sorted, stable, and deduplicated.
///
/// # Edge cases handled
///
/// - **Empty graph**: returns empty vec.
/// - **Pure DAG**: every node drains, returns empty vec.
/// - **Self-loop**: rejected at `record`-time, so cannot appear here.
/// - **Disconnected cycles**: every cycle is reported (we drain all
///   sinks before classifying).
/// - **Diamonds**: a → b, a → c, b → d, c → d does not flag.
#[must_use]
pub(crate) fn kahn_cycle_members(graph: &ImportGraph) -> Vec<String> {
    let mut indeg = build_indegree_map(graph);
    let mut queue: VecDeque<String> = indeg
        .iter()
        .filter(|(_, v)| **v == 0)
        .map(|(k, _)| k.clone())
        .collect();
    while let Some(node) = queue.pop_front() {
        indeg.remove(&node);
        drain_targets(graph, &node, &mut indeg, &mut queue);
    }
    indeg.into_keys().collect()
}

fn build_indegree_map(graph: &ImportGraph) -> BTreeMap<String, usize> {
    let mut indeg: BTreeMap<String, usize> = BTreeMap::new();
    for (from, tos) in graph.edges() {
        indeg.entry(from.clone()).or_insert(0);
        for to in tos {
            *indeg.entry(to.clone()).or_insert(0) += 1;
        }
    }
    indeg
}

fn drain_targets(
    graph: &ImportGraph,
    node: &str,
    indeg: &mut BTreeMap<String, usize>,
    queue: &mut VecDeque<String>,
) {
    let Some(targets) = graph.edges().get(node) else {
        return;
    };
    for to in targets {
        decrement_and_queue(indeg, queue, to);
    }
}

fn decrement_and_queue(
    indeg: &mut BTreeMap<String, usize>,
    queue: &mut VecDeque<String>,
    to: &str,
) {
    if let Some(d) = indeg.get_mut(to) {
        *d = d.saturating_sub(1);
        if *d == 0 {
            queue.push_back(to.to_owned());
        }
    }
}
