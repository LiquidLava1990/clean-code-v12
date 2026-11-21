//! Per-batch lexical call-graph resolver.
//!
//! Runs as a post-pass after AST lift. For every [`NodeKind::Call`] node the
//! resolver:
//!
//! 1. Reads the callee text from `callee_ref` (every frontend lifts it to
//!    that property — see `cc-frontend-{python,typescript,go,rust}`).
//! 2. Strips language-specific module / receiver prefixes via the caller-
//!    supplied [`StripPrefixFn`] — Python / Go / TypeScript split on `.`,
//!    Rust on `::`. The bare last segment is what the lookup matches.
//! 3. Looks up that bare name in two scopes, in order:
//!    - the enclosing [`NodeKind::Function`] / [`NodeKind::Method`]'s own
//!      AST descendants (local bindings),
//!    - the file-level name table built from every direct child of every
//!      [`NodeKind::File`] / [`NodeKind::Module`] in the batch.
//! 4. Emits one [`EdgeKind::CG_CALLS`] edge per match. Over-approximation
//!    is acceptable in this phase — multiple matches on the same bare
//!    name (e.g. method overloads) all get edges.
//!
//! Cross-file resolution is explicitly out of scope; that lives in
//! `cc-cpg-store` (Phase 1 W2). This module produces zero false negatives
//! within a single file and zero false positives across the project (it
//! never resolves to a node it didn't see in the batch).
//!
//! Identifier-level [`EdgeKind::REFERENCES`] emission is handled by
//! [`crate::default_resolver`]; the two passes are separate so frontends
//! that override one don't have to override the other.

use std::collections::HashMap;

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind};

use crate::errors::ResolveError;
use crate::query::{ast_parent, node_kind, nodes_of_kind, string_prop};

/// Strip a language-specific module / receiver prefix off a callee text and
/// return the bare name to look up.
///
/// Implementations should be cheap and total — return the input itself if
/// no prefix applies. Examples:
///
/// - Python: `"module.fn"` -> `"fn"`, `"obj.method"` -> `"method"`
/// - Rust:   `"std::time::sleep"` -> `"sleep"`, `"self::helper"` -> `"helper"`
/// - Go:     `"pkg.Func"` -> `"Func"`, `"recv.Method"` -> `"Method"`
/// - TS:     `"obj.method"` -> `"method"`, `"ns.Class.fn"` -> `"fn"`
pub type StripPrefixFn = fn(&str) -> &str;

/// Default strip — split on `.` and take the last segment. Suitable for
/// Python, TypeScript, and Go.
#[must_use]
pub fn strip_dot_prefix(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

/// Rust strip — split on `::` and take the last segment.
#[must_use]
pub fn strip_colon_prefix(callee: &str) -> &str {
    callee.rsplit("::").next().unwrap_or(callee)
}

/// Resolve every [`NodeKind::Call`] in `batch` to its in-batch callee
/// [`NodeKind::Function`] / [`NodeKind::Method`] target(s) and emit
/// [`EdgeKind::CG_CALLS`] edges.
///
/// `strip` strips language-specific module / receiver prefixes off the
/// callee text before lookup; pass [`strip_dot_prefix`] for Python /
/// TS / Go and [`strip_colon_prefix`] for Rust.
///
/// # Errors
///
/// Returns `Ok(())` in all observed cases — the only failure path
/// (`push_edge` rejecting a dangling endpoint) cannot trigger because every
/// endpoint id was just produced by this same batch. The `Result` is kept
/// in the signature for forward-compat with cross-file resolution.
///
/// # Panics
///
/// Panics if `push_edge` rejects a dangling endpoint — by construction
/// this is unreachable, since every node id was just produced by this
/// same batch. Treated as `unreachable!()` rather than a soft error so
/// a true regression (e.g. id allocation bug) surfaces loudly.
pub fn resolve(batch: &mut CpgWriteBatch, strip: StripPrefixFn) -> Result<(), ResolveError> {
    let file_table = build_file_name_table(batch);
    let pending = collect_call_resolutions(batch, &file_table, strip);
    for (call, target) in pending {
        batch
            .push_edge(EdgeKind::CG_CALLS, call, target)
            .expect("call and target ids both came from this batch");
    }
    Ok(())
}

/// `name -> [function/method/class node ids]` covering every Function /
/// Method / Class in the batch whose enclosing scope is `File`, `Module`,
/// or `Class` — i.e. anything reachable as a "file-level" name without
/// crossing into another function body.
///
/// Including methods in the table is intentional: a call site like
/// `self.helper()` strips the receiver to `helper` and matches against
/// every method named `helper` in the batch. Phase-1 over-approximation
/// is acceptable per the task contract; cross-file resolution lives in
/// the persistent store.
fn build_file_name_table(batch: &CpgWriteBatch) -> HashMap<String, Vec<NodeId>> {
    let mut table: HashMap<String, Vec<NodeId>> = HashMap::new();
    for kind in [NodeKind::Function, NodeKind::Method, NodeKind::Class] {
        for node in nodes_of_kind(batch, kind) {
            if !is_module_or_class_scoped(batch, node.id) {
                continue;
            }
            if let Some(name) = string_prop(batch, node.id, "name") {
                table.entry(name.to_owned()).or_default().push(node.id);
            }
        }
    }
    table
}

/// True iff `id`'s AST parent is a `File`, `Module`, or `Class` — the
/// scopes whose declarations are reachable from any call site in the
/// same file without local-scope shadowing.
fn is_module_or_class_scoped(batch: &CpgWriteBatch, id: NodeId) -> bool {
    matches!(
        ast_parent(batch, id).and_then(|p| node_kind(batch, p)),
        Some(NodeKind::File | NodeKind::Module | NodeKind::Class)
    )
}

/// Walk every `Call` node and return the list of edges to emit. Pure
/// read-only over `batch` so the mutable edge-push step is decoupled from
/// the resolution logic.
fn collect_call_resolutions(
    batch: &CpgWriteBatch,
    file_table: &HashMap<String, Vec<NodeId>>,
    strip: StripPrefixFn,
) -> Vec<(NodeId, NodeId)> {
    let mut out = Vec::new();
    for call in nodes_of_kind(batch, NodeKind::Call) {
        let Some(callee_text) = string_prop(batch, call.id, "callee_ref") else {
            continue;
        };
        if callee_text.is_empty() {
            continue;
        }
        let bare = strip(callee_text);
        if bare.is_empty() {
            continue;
        }
        for target in resolve_bare_name(batch, call.id, bare, file_table) {
            out.push((call.id, target));
        }
    }
    out
}

/// Resolve a bare callee name first against the enclosing function's local
/// scope, then against the file-level name table.
///
/// Local-scope shadowing wins: if `bar` is both a local closure inside `foo`
/// and a file-level function, the call inside `foo` resolves to the local.
fn resolve_bare_name(
    batch: &CpgWriteBatch,
    call_id: NodeId,
    bare: &str,
    file_table: &HashMap<String, Vec<NodeId>>,
) -> Vec<NodeId> {
    if let Some(locals) = lookup_in_enclosing_scope(batch, call_id, bare) {
        if !locals.is_empty() {
            return locals;
        }
    }
    file_table.get(bare).cloned().unwrap_or_default()
}

/// Walk up the `AST_PARENT` chain from `call_id`. At each enclosing
/// `Function` / `Method`, scan its descendants for a function or method
/// declaration whose `name` matches `bare`.
fn lookup_in_enclosing_scope(
    batch: &CpgWriteBatch,
    call_id: NodeId,
    bare: &str,
) -> Option<Vec<NodeId>> {
    let mut cursor = call_id;
    while let Some(parent) = ast_parent(batch, cursor) {
        if matches!(
            node_kind(batch, parent),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            let hits = scan_descendants_for(batch, parent, bare);
            if !hits.is_empty() {
                return Some(hits);
            }
        }
        cursor = parent;
    }
    None
}

/// Collect every descendant of `scope` (Function / Method) whose kind is
/// `Function` / `Method` and whose `name` matches `bare`. Uses a BFS over
/// `AST_PARENT` incoming edges so closures-inside-closures resolve correctly.
fn scan_descendants_for(batch: &CpgWriteBatch, scope: NodeId, bare: &str) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut frontier = vec![scope];
    while let Some(parent) = frontier.pop() {
        for edge in batch.edges() {
            if edge.kind != EdgeKind::AST_PARENT || edge.to != parent {
                continue;
            }
            let child = edge.from;
            if child == scope {
                continue;
            }
            if matches!(
                node_kind(batch, child),
                Some(NodeKind::Function | NodeKind::Method)
            ) && string_prop(batch, child, "name") == Some(bare)
            {
                out.push(child);
            }
            frontier.push(child);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, Value};

    fn add_named(batch: &mut CpgWriteBatch, kind: NodeKind, name: &str) -> NodeId {
        batch.push_node(NodeBuilder::new(kind).with_prop("name", Value::String(name.to_owned())))
    }

    fn add_call(batch: &mut CpgWriteBatch, callee_ref: &str) -> NodeId {
        batch.push_node(
            NodeBuilder::new(NodeKind::Call)
                .with_prop("callee_ref", Value::String(callee_ref.to_owned())),
        )
    }

    fn link_parent(batch: &mut CpgWriteBatch, child: NodeId, parent: NodeId) {
        batch
            .push_edge(EdgeKind::AST_PARENT, child, parent)
            .expect("dangling AST_PARENT in test fixture");
    }

    fn count_cg_calls(batch: &CpgWriteBatch, from: NodeId, to: NodeId) -> usize {
        batch
            .edges()
            .iter()
            .filter(|e| e.kind == EdgeKind::CG_CALLS && e.from == from && e.to == to)
            .count()
    }

    #[test]
    fn strip_dot_takes_last_segment() {
        assert_eq!(strip_dot_prefix("foo"), "foo");
        assert_eq!(strip_dot_prefix("a.b.c"), "c");
        assert_eq!(strip_dot_prefix(""), "");
    }

    #[test]
    fn strip_colon_takes_last_segment() {
        assert_eq!(strip_colon_prefix("foo"), "foo");
        assert_eq!(strip_colon_prefix("std::time::sleep"), "sleep");
    }

    #[test]
    fn resolves_top_level_call() {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let f_a = add_named(&mut batch, NodeKind::Function, "a");
        let f_b = add_named(&mut batch, NodeKind::Function, "b");
        link_parent(&mut batch, f_a, module);
        link_parent(&mut batch, f_b, module);

        let call = add_call(&mut batch, "b");
        link_parent(&mut batch, call, f_a);

        resolve(&mut batch, strip_dot_prefix).expect("resolve");
        assert_eq!(count_cg_calls(&batch, call, f_b), 1);
    }

    #[test]
    fn resolves_qualified_callee_via_strip() {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let f_a = add_named(&mut batch, NodeKind::Function, "a");
        let f_b = add_named(&mut batch, NodeKind::Function, "b");
        link_parent(&mut batch, f_a, module);
        link_parent(&mut batch, f_b, module);

        let call = add_call(&mut batch, "self.b");
        link_parent(&mut batch, call, f_a);

        resolve(&mut batch, strip_dot_prefix).expect("resolve");
        assert_eq!(count_cg_calls(&batch, call, f_b), 1);
    }

    #[test]
    fn local_scope_shadows_file_scope() {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let outer = add_named(&mut batch, NodeKind::Function, "outer");
        let file_helper = add_named(&mut batch, NodeKind::Function, "helper");
        link_parent(&mut batch, outer, module);
        link_parent(&mut batch, file_helper, module);

        // `outer` declares a nested `helper` that shadows the file-level one.
        let local_helper = add_named(&mut batch, NodeKind::Function, "helper");
        link_parent(&mut batch, local_helper, outer);

        let call = add_call(&mut batch, "helper");
        link_parent(&mut batch, call, outer);

        resolve(&mut batch, strip_dot_prefix).expect("resolve");
        assert_eq!(count_cg_calls(&batch, call, local_helper), 1);
        assert_eq!(count_cg_calls(&batch, call, file_helper), 0);
    }

    #[test]
    fn unresolved_callee_emits_no_edge() {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let f_a = add_named(&mut batch, NodeKind::Function, "a");
        link_parent(&mut batch, f_a, module);
        let call = add_call(&mut batch, "library_func");
        link_parent(&mut batch, call, f_a);

        resolve(&mut batch, strip_dot_prefix).expect("resolve");
        let any_call_edge = batch.edges().iter().any(|e| e.kind == EdgeKind::CG_CALLS);
        assert!(!any_call_edge, "no in-batch target -> no CG_CALLS edge");
    }

    #[test]
    fn empty_callee_text_is_skipped() {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let f_a = add_named(&mut batch, NodeKind::Function, "a");
        link_parent(&mut batch, f_a, module);
        let call = add_call(&mut batch, "");
        link_parent(&mut batch, call, f_a);

        resolve(&mut batch, strip_dot_prefix).expect("resolve");
        assert!(!batch.edges().iter().any(|e| e.kind == EdgeKind::CG_CALLS));
    }
}
