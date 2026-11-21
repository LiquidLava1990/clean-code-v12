//! Lexical-scope name resolver used by frontends that don't override
//! [`crate::LanguageFrontend::resolve_names`].
//!
//! The algorithm is intentionally simple — walk every `Identifier` node,
//! traverse its `AST_PARENT` chain looking for a matching declaration
//! (`Variable`, `Parameter`, `Function`, `Class`, `Module`, `Import`), and
//! emit a `REFERENCES` edge to the nearest match. Identifiers without a
//! match are left without an outbound `REFERENCES` edge — downstream type
//! inference / call resolution treats them as `Unresolved`.
//!
//! Languages with non-lexical scoping (Python `global` / `nonlocal`,
//! TypeScript `var` hoisting, Go package-level visibility) override
//! `resolve_names` and call language-specific logic instead.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind};

use crate::errors::ResolveError;
use crate::query::{ast_children, ast_parent, node_kind, nodes_of_kind, string_prop};

/// Default lexical-scope resolver.
///
/// Iterates every `Identifier` node in the batch, walks its `AST_PARENT`
/// chain, and emits a `REFERENCES` edge to the first declaration whose
/// `name` matches. Identifiers without a match are left without a
/// `REFERENCES` edge; downstream type inference treats them as `Unresolved`.
///
/// # Errors
///
/// Returns `Ok(())` in all observed cases — the only failure path
/// (`push_edge` rejecting a dangling endpoint) cannot trigger because both
/// endpoints come from the same batch we just walked. The `Result` is kept
/// in the signature for forward-compatibility once the resolver grows
/// project-wide cross-file lookups.
pub fn resolve(store: &mut CpgWriteBatch) -> Result<(), ResolveError> {
    for (ident, decl) in collect_pending_resolutions(store) {
        store
            .push_edge(EdgeKind::REFERENCES, ident, decl)
            .expect("identifier and declaration ids both came from this batch");
    }
    Ok(())
}

/// Collect every (identifier, declaration) pair the resolver would emit.
///
/// Pulled out of [`resolve`] so the mutable edge-push step is decoupled
/// from the read-only scope walk; the latter is what we unit-test.
fn collect_pending_resolutions(store: &CpgWriteBatch) -> Vec<(NodeId, NodeId)> {
    let identifier_ids: Vec<NodeId> = nodes_of_kind(store, NodeKind::Identifier)
        .map(|n| n.id)
        .collect();
    identifier_ids
        .into_iter()
        .filter_map(|ident| pair_identifier_with_decl(store, ident))
        .collect()
}

/// Pair a single `Identifier` with its lexical declaration, if one exists.
fn pair_identifier_with_decl(store: &CpgWriteBatch, ident: NodeId) -> Option<(NodeId, NodeId)> {
    let name = string_prop(store, ident, "name")?;
    let decl = lookup_in_scope_chain(store, ident, name)?;
    Some((ident, decl))
}

/// Walk the `AST_PARENT` chain from `start`, returning the first declaration
/// in any enclosing scope whose `name` property matches `target`.
fn lookup_in_scope_chain(store: &CpgWriteBatch, start: NodeId, target: &str) -> Option<NodeId> {
    let mut cursor = start;
    while let Some(parent) = ast_parent(store, cursor) {
        if let Some(decl) = scan_scope_for(store, parent, target) {
            return Some(decl);
        }
        cursor = parent;
    }
    None
}

/// Scan a single scope-bearing parent for a declaration matching `target`.
///
/// Scope-bearing kinds: `Module`, `Class`, `Function`, `Method`, `Block`.
/// Other parents are transparent — we still inspect their declarations so
/// flat structures (e.g. parameter lists) resolve correctly.
fn scan_scope_for(store: &CpgWriteBatch, parent: NodeId, target: &str) -> Option<NodeId> {
    for child in ast_children(store, parent) {
        if !is_declaration_kind_at(store, child) {
            continue;
        }
        if string_prop(store, child, "name") == Some(target) {
            return Some(child);
        }
    }
    None
}

/// `true` iff the node at `id` is a binding-introducing kind.
fn is_declaration_kind_at(store: &CpgWriteBatch, id: NodeId) -> bool {
    match node_kind(store, id) {
        Some(kind) => is_declaration_kind(kind),
        None => false,
    }
}

/// `true` for node kinds that introduce a binding into their enclosing scope.
const fn is_declaration_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Variable
            | NodeKind::Parameter
            | NodeKind::Function
            | NodeKind::Method
            | NodeKind::Class
            | NodeKind::Module
            | NodeKind::Import
    )
}

#[cfg(test)]
mod tests {
    //! Resolver tests build a synthetic CPG with nested scopes:
    //!
    //! ```text
    //! Module "m"
    //! └── Function "outer"
    //!     ├── Parameter "x"            (declaration A)
    //!     └── Block
    //!         ├── Variable "x"         (declaration B — shadows A)
    //!         └── Identifier "x"       (resolves to B, not A)
    //! ```
    //!
    //! and assert that the resolver picks the *innermost* binding.
    use super::*;
    use crate::query::first_outgoing_target;
    use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, Value};

    fn add_named(batch: &mut CpgWriteBatch, kind: NodeKind, name: &str) -> NodeId {
        batch.push_node(NodeBuilder::new(kind).with_prop("name", Value::String(name.to_owned())))
    }

    fn link_parent(batch: &mut CpgWriteBatch, child: NodeId, parent: NodeId) {
        batch
            .push_edge(EdgeKind::AST_PARENT, child, parent)
            .expect("dangling AST_PARENT in test fixture");
    }

    fn build_shadowing_fixture() -> (CpgWriteBatch, NodeId, NodeId) {
        let mut batch = CpgWriteBatch::new();
        let module = add_named(&mut batch, NodeKind::Module, "m");
        let outer = add_named(&mut batch, NodeKind::Function, "outer");
        link_parent(&mut batch, outer, module);

        let param_x = add_named(&mut batch, NodeKind::Parameter, "x");
        link_parent(&mut batch, param_x, outer);

        let block_id = batch.push_node(NodeBuilder::new(NodeKind::Block));
        link_parent(&mut batch, block_id, outer);

        let var_x_inner = add_named(&mut batch, NodeKind::Variable, "x");
        link_parent(&mut batch, var_x_inner, block_id);

        let ident_x = add_named(&mut batch, NodeKind::Identifier, "x");
        link_parent(&mut batch, ident_x, block_id);

        (batch, ident_x, var_x_inner)
    }

    #[test]
    fn default_resolver_lexical_scope() {
        let (mut batch, ident_x, var_x_inner) = build_shadowing_fixture();
        resolve(&mut batch).expect("resolver should succeed");

        let target = first_outgoing_target(&batch, ident_x, EdgeKind::REFERENCES)
            .expect("identifier should have REFERENCES edge");
        assert_eq!(
            target, var_x_inner,
            "innermost Variable should shadow outer Parameter"
        );
    }
}
