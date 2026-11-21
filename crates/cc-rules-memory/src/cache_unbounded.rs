//! `cc.memory.cache_unbounded` — module / class scope dict / list / map
//! / vec with insert-style calls but no remove-style calls anywhere in
//! the same batch.
//!
//! Heuristic:
//!
//! 1. Enumerate [`NodeKind::Variable`] / [`NodeKind::Write`] nodes whose
//!    parent is a [`NodeKind::Module`] / [`NodeKind::File`] /
//!    [`NodeKind::Class`] (top-level / class-field scope).
//! 2. Filter to bindings whose `initializer` looks like a fresh empty
//!    container: `dict()`, `{}`, `[]`, `set()`, `HashMap::new`,
//!    `Vec::new`, `BTreeMap::new`, `new Map()`, `new Set()`.
//! 3. For the binding's `target`, look across every [`NodeKind::Call`]
//!    in the batch:
//!    - At least one call whose receiver is `target` and whose method
//!      is an insert-style verb (`append`, `push`, `insert`, `add`,
//!      `set`, `__setitem__`).
//!    - Zero calls whose receiver is `target` and whose method is a
//!      remove-style verb (`pop`, `clear`, `delete`, `shift`, `remove`,
//!      `evict`, `__delitem__`).
//! 4. If `lru_cache(maxsize=...)` / `LruCache::new` is referenced in the
//!    same file as the binding, skip — the user has explicitly bounded.
//!
//! Phase-3 simplification: scan the whole batch (not just the same
//! file) for inserts / removes; cross-file caches are rare and the
//! noise floor stays low because the binding-shape check is strict.

use cc_cpg::{CpgWriteBatch, Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, MemoryFindingBlueprint,
};

/// Family-6 probe R-MEM-CACHE-UNBOUNDED.
#[derive(Debug, Default, Clone, Copy)]
pub struct CacheUnboundedRule;

const EMPTY_CONTAINERS: &[&str] = &[
    "dict()",
    "list()",
    "set()",
    "{}",
    "[]",
    "HashMap::new",
    "Vec::new",
    "BTreeMap::new",
    "HashSet::new",
    "new Map()",
    "new Set()",
    "new Array()",
];

const INSERT_VERBS: &[&str] = &[
    "append",
    "push",
    "insert",
    "add",
    "set",
    "__setitem__",
    "push_back",
    "extend",
];

const REMOVE_VERBS: &[&str] = &[
    "pop",
    "clear",
    "delete",
    "del",
    "shift",
    "remove",
    "evict",
    "__delitem__",
    "drain",
    "truncate",
];

const BOUNDED_HINTS: &[&str] = &[
    "lru_cache",
    "LruCache",
    "TTLCache",
    "BoundedCache",
    "maxsize",
];

impl Rule for CacheUnboundedRule {
    fn rule_id(&self) -> &'static str {
        "cc.memory.cache_unbounded"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Memory
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "module-scope container with inserts but no removes — unbounded cache"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_write(ctx: &RuleContext<'_>, write: &Node) -> Option<Finding> {
    if !is_top_level(ctx.batch, write.id) {
        return None;
    }
    let initializer = string_prop(ctx.batch, write.id, "initializer")?;
    if !is_empty_container(initializer) {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target")?;
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if has_bounded_hint(ctx.batch) {
        return None;
    }
    if !has_inserts(ctx.batch, target) {
        return None;
    }
    if has_removes(ctx.batch, target) {
        return None;
    }
    let location = location_from_node(ctx.batch, write.id, path);
    Some(build_finding(MemoryFindingBlueprint {
        rule_id: "cc.memory.cache_unbounded",
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{target}` is a module-scope cache with no eviction"),
        explanation: format!(
            "`{target}` is bound to an empty container at module / class scope \
             and gets inserts (append / push / insert / `[k]=v`) but never \
             removes (pop / clear / delete / shift). Memory grows monotonically \
             — under load this is a leak."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Cap with `functools.lru_cache(maxsize=...)`, an LRU / TTL cache \
             type, or pair every insert with an eviction policy. If the \
             container is intentionally unbounded, document the lifetime + \
             expected upper bound."
                .into(),
        ),
        snippet: initializer.to_owned(),
        weight: 3,
    }))
}

fn is_top_level(batch: &CpgWriteBatch, id: NodeId) -> bool {
    matches!(
        ast_parent(batch, id).and_then(|p| node_kind(batch, p)),
        Some(NodeKind::Module | NodeKind::File | NodeKind::Class)
    )
}

fn is_empty_container(initializer: &str) -> bool {
    let trimmed = initializer.trim();
    EMPTY_CONTAINERS
        .iter()
        .any(|needle| trimmed == *needle || trimmed.contains(needle))
}

fn has_inserts(batch: &CpgWriteBatch, target: &str) -> bool {
    nodes_of_kind(batch, NodeKind::Call)
        .any(|call| call_matches(batch, call.id, target, INSERT_VERBS))
}

fn has_removes(batch: &CpgWriteBatch, target: &str) -> bool {
    nodes_of_kind(batch, NodeKind::Call)
        .any(|call| call_matches(batch, call.id, target, REMOVE_VERBS))
}

fn call_matches(batch: &CpgWriteBatch, id: NodeId, target: &str, verbs: &[&str]) -> bool {
    if string_prop(batch, id, "receiver") != Some(target) {
        return false;
    }
    string_prop(batch, id, "method").is_some_and(|m| verbs.contains(&m))
}

fn has_bounded_hint(batch: &CpgWriteBatch) -> bool {
    nodes_of_kind(batch, NodeKind::Call).any(|call| {
        let text = callee_text(batch, call.id);
        BOUNDED_HINTS.iter().any(|hint| text.contains(hint))
    }) || nodes_of_kind(batch, NodeKind::Decorator).any(|dec| {
        string_prop(batch, dec.id, "name")
            .is_some_and(|n| BOUNDED_HINTS.iter().any(|hint| n.contains(hint)))
    })
}
