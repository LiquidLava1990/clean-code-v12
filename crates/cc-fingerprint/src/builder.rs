//! Incremental [`FingerprintBuilder`] — accepts one
//! [`cc_cpg::CpgWriteBatch`] per file and rolls a finalized [`Fingerprint`].
//!
//! The builder is deliberately resilient: missing or wrong-typed properties
//! are skipped rather than fatal, with a `tracing::warn` for observability.
//! A frontend that lifts a half-formed file should still be able to
//! contribute to the rest of the fingerprint without poisoning the run.

use cc_cpg::{CpgWriteBatch, EdgeKind, Node, NodeId, NodeKind, Value};
use tracing::trace;

use crate::error::{FingerprintError, FingerprintResult};
use crate::errors::ErrorPatternMap;
use crate::fingerprint::{Fingerprint, SampleSize};
use crate::imports::LayerGraph;
use crate::naming::NamingDistribution;
use crate::test_style::{is_assertion_call, is_test_function, TestStyleProfile};

/// Node kinds that carry a `name` property contributing to the per-kind
/// naming distribution.
const NAMING_KINDS: &[NodeKind] = &[
    NodeKind::Function,
    NodeKind::Method,
    NodeKind::Class,
    NodeKind::Variable,
    NodeKind::Parameter,
];

/// Incrementally builds a [`Fingerprint`] across many files.
///
/// Frontends call [`Self::add_file`] once per parsed-and-lifted file, then
/// [`Self::finalize`] once at the end of the scan.
#[derive(Debug, Default)]
pub struct FingerprintBuilder {
    naming: NamingDistribution,
    errors: ErrorPatternMap,
    layering: LayerGraph,
    test_style: TestStyleProfile,
    files: u32,
}

impl FingerprintBuilder {
    /// Construct a fresh builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Roll one batch into the fingerprint.
    ///
    /// `language` is captured for future per-language calibration (currently
    /// unused — the builder is language-agnostic at this stage).
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintError`] only on hard schema violations that the
    /// caller can act on. Soft issues (an `Import` with no recognisable
    /// source) are skipped and logged at `trace` level.
    pub fn add_file(&mut self, batch: &CpgWriteBatch, language: &str) -> FingerprintResult<()> {
        trace!(
            target: "cc_fingerprint",
            language = language,
            nodes = batch.nodes().len(),
            edges = batch.edges().len(),
            "rolling batch into fingerprint"
        );
        self.files = self.files.saturating_add(1);
        let file_path = file_path_from_batch(batch);
        let module_path = module_path_from_batch(batch);

        for node in batch.nodes() {
            self.absorb_naming(node)?;
            self.absorb_test_function(node, file_path.as_deref(), batch);
            self.absorb_try_catches(node, batch);
        }
        self.absorb_imports(batch, module_path.as_deref())?;
        self.absorb_raises(batch);
        Ok(())
    }

    /// Finalize and return the built [`Fingerprint`].
    #[must_use]
    pub fn finalize(self) -> Fingerprint {
        let identifiers = self.naming.sample_count();
        Fingerprint {
            naming: self.naming,
            errors: self.errors,
            layering: self.layering,
            test_style: self.test_style,
            sample_size: SampleSize {
                files: self.files,
                identifiers,
            },
        }
    }

    fn absorb_naming(&mut self, node: &Node) -> FingerprintResult<()> {
        if !NAMING_KINDS.contains(&node.kind) {
            return Ok(());
        }
        let Some(name) = read_name(node)? else {
            return Ok(());
        };
        self.naming.record(node.kind, name);
        Ok(())
    }

    fn absorb_test_function(
        &mut self,
        node: &Node,
        file_path: Option<&str>,
        batch: &CpgWriteBatch,
    ) {
        if !matches!(node.kind, NodeKind::Function | NodeKind::Method) {
            return;
        }
        let Some(Value::String(name)) = node.prop("name") else {
            return;
        };
        if !is_test_function(name, file_path) {
            return;
        }
        self.test_style.record_test_fn();
        // Walk Calls whose AST_PARENT chain leads back to this function and
        // record their callee names if they look like assertions. We use
        // AST_PARENT as the proxy for "inside this function".
        let fn_id = node.id;
        for call in batch.nodes().iter().filter(|n| n.kind == NodeKind::Call) {
            if !is_descendant_of(batch, call.id, fn_id) {
                continue;
            }
            if let Some(Value::String(callee)) = call.prop("callee_name") {
                if is_assertion_call(callee) {
                    self.test_style.record_assertion(callee);
                }
            }
        }
    }

    fn absorb_try_catches(&mut self, node: &Node, batch: &CpgWriteBatch) {
        if node.kind != NodeKind::Try {
            return;
        }
        // Per schema: `catches: [ExceptType]` is a NodeList of Type nodes.
        if let Some(Value::NodeList(refs)) = node.prop("catches") {
            for ty_id in refs {
                if let Some(name) = lookup_type_name(batch, *ty_id) {
                    self.errors.record(name);
                }
            }
        }
        // Some frontends prefer a flat string list under `catch_names`.
        if let Some(Value::String(name)) = node.prop("catch_name") {
            self.errors.record(name);
        }
    }

    fn absorb_imports(
        &mut self,
        batch: &CpgWriteBatch,
        from_module: Option<&str>,
    ) -> FingerprintResult<()> {
        for node in batch.nodes() {
            if node.kind != NodeKind::Import {
                continue;
            }
            let Some(target) = read_import_target(node) else {
                continue;
            };
            let from = from_module.unwrap_or("<unknown>");
            if from == "<unknown>" {
                return Err(FingerprintError::DanglingImport {
                    from: from.to_owned(),
                });
            }
            self.layering.record(from, target);
        }
        Ok(())
    }

    fn absorb_raises(&mut self, batch: &CpgWriteBatch) {
        for edge in batch.edges() {
            if edge.kind != EdgeKind::RAISES {
                continue;
            }
            if let Some(name) = lookup_type_name(batch, edge.to) {
                self.errors.record(name);
            }
        }
    }
}

fn read_name(node: &Node) -> FingerprintResult<Option<&str>> {
    let Some(value) = node.prop("name") else {
        // A name-bearing node without `name` is a soft issue; we skip
        // rather than fail the whole batch. Frontends that want hard
        // enforcement can validate at lift time.
        return Ok(None);
    };
    match value {
        Value::String(s) => Ok(Some(s.as_str())),
        other => Err(FingerprintError::WrongPropertyTag {
            node_id: node.id.get(),
            property: "name",
            expected_tag: "string",
            actual_tag: other.tag(),
        }),
    }
}

fn read_import_target(node: &Node) -> Option<&str> {
    // Accept either schema-canonical `source` or the legacy `target` alias.
    if let Some(Value::String(s)) = node.prop("source") {
        return Some(s.as_str());
    }
    if let Some(Value::String(s)) = node.prop("target") {
        return Some(s.as_str());
    }
    None
}

fn lookup_type_name(batch: &CpgWriteBatch, ty_id: NodeId) -> Option<&str> {
    let node = batch.nodes().iter().find(|n| n.id == ty_id)?;
    if !matches!(node.kind, NodeKind::Type | NodeKind::Class) {
        return None;
    }
    match node.prop("name")? {
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

fn file_path_from_batch(batch: &CpgWriteBatch) -> Option<String> {
    let file = batch.nodes().iter().find(|n| n.kind == NodeKind::File)?;
    match file.prop("path")? {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn module_path_from_batch(batch: &CpgWriteBatch) -> Option<String> {
    let module = batch.nodes().iter().find(|n| n.kind == NodeKind::Module)?;
    if let Some(Value::String(s)) = module.prop("qualified_name") {
        return Some(s.clone());
    }
    if let Some(Value::String(s)) = module.prop("name") {
        return Some(s.clone());
    }
    None
}

/// Walk `AST_PARENT` edges (child → parent) up from `start` and return true
/// if we reach `ancestor`. Bounded by the batch's edge count to guarantee
/// termination on malformed inputs.
fn is_descendant_of(batch: &CpgWriteBatch, start: NodeId, ancestor: NodeId) -> bool {
    if start == ancestor {
        return true;
    }
    let bound = batch.edges().len() + 1;
    let mut current = start;
    for _ in 0..bound {
        let parent_edge = batch
            .edges()
            .iter()
            .find(|e| e.kind == EdgeKind::AST_PARENT && e.from == current);
        let Some(edge) = parent_edge else {
            return false;
        };
        if edge.to == ancestor {
            return true;
        }
        current = edge.to;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_cpg::{NodeBuilder, Value};

    fn push_named(batch: &mut CpgWriteBatch, kind: NodeKind, name: &str) -> NodeId {
        batch.push_node(NodeBuilder::new(kind).with_prop("name", Value::String(name.to_owned())))
    }

    #[test]
    fn add_file_increments_files() {
        let mut b = FingerprintBuilder::new();
        let batch = CpgWriteBatch::new();
        b.add_file(&batch, "rust").expect("empty batch ok");
        b.add_file(&batch, "rust").expect("empty batch ok");
        let fp = b.finalize();
        assert_eq!(fp.sample_size.files, 2);
        assert_eq!(fp.sample_size.identifiers, 0);
    }

    #[test]
    fn naming_recorded_for_function() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        push_named(&mut batch, NodeKind::Function, "my_function");
        push_named(&mut batch, NodeKind::Function, "another_one");
        b.add_file(&batch, "py").expect("ok");
        let fp = b.finalize();
        let counts = fp.naming.counts(NodeKind::Function).expect("recorded");
        assert_eq!(counts.snake, 2);
    }

    #[test]
    fn missing_name_is_soft_skip() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        batch.push_node(NodeBuilder::new(NodeKind::Function));
        b.add_file(&batch, "py")
            .expect("missing name should be soft");
    }

    #[test]
    fn wrong_name_tag_is_hard_error() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        batch.push_node(NodeBuilder::new(NodeKind::Function).with_prop("name", Value::Int(7)));
        let err = b.add_file(&batch, "py").expect_err("wrong tag");
        assert!(matches!(err, FingerprintError::WrongPropertyTag { .. }));
    }

    #[test]
    fn import_recorded_into_layer_graph() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        batch.push_node(
            NodeBuilder::new(NodeKind::Module).with_prop("name", Value::String("A".into())),
        );
        batch.push_node(
            NodeBuilder::new(NodeKind::Import).with_prop("source", Value::String("B".into())),
        );
        b.add_file(&batch, "py").expect("ok");
        let fp = b.finalize();
        let targets = fp.layering.targets("A").expect("A imports something");
        assert!(targets.contains("B"));
    }

    #[test]
    fn try_catches_recorded_into_errors() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        let ty = batch.push_node(
            NodeBuilder::new(NodeKind::Type).with_prop("name", Value::String("ValueError".into())),
        );
        batch.push_node(
            NodeBuilder::new(NodeKind::Try).with_prop("catches", Value::NodeList(vec![ty])),
        );
        b.add_file(&batch, "py").expect("ok");
        let fp = b.finalize();
        assert_eq!(fp.errors.count("ValueError"), 1);
    }

    #[test]
    fn raises_edge_recorded_into_errors() {
        let mut b = FingerprintBuilder::new();
        let mut batch = CpgWriteBatch::new();
        let func = batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String("do_thing".into())),
        );
        let ty = batch.push_node(
            NodeBuilder::new(NodeKind::Type)
                .with_prop("name", Value::String("RuntimeError".into())),
        );
        batch.push_edge(EdgeKind::RAISES, func, ty).expect("ok");
        b.add_file(&batch, "py").expect("ok");
        let fp = b.finalize();
        assert_eq!(fp.errors.count("RuntimeError"), 1);
    }
}
