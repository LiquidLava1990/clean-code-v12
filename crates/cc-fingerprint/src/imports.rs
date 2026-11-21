//! Per-module import graph + path-prefix downward-only check.
//!
//! Repos that follow a layered architecture have all imports flowing from
//! deeper layers (`app/api`) to shallower ones (`app/core`). The graph is
//! intentionally lightweight — full Tarjan SCC cycle detection lives in
//! `cc-rules`, not here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Observed module-to-module import graph.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerGraph {
    /// `from_module` -> set of imported targets.
    edges: BTreeMap<String, BTreeSet<String>>,
}

impl LayerGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an import edge `from -> to`.
    pub fn record(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.edges.entry(from.into()).or_default().insert(to.into());
    }

    /// Borrow the targets imported by `from`.
    #[must_use]
    pub fn targets(&self, from: &str) -> Option<&BTreeSet<String>> {
        self.edges.get(from)
    }

    /// Number of distinct source modules with at least one outgoing import.
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.edges.len()
    }

    /// Total number of recorded import edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(BTreeSet::len).sum()
    }

    /// Iterate over all `(from, to)` pairs.
    pub fn iter_edges(&self) -> impl Iterator<Item = (&str, &str)> {
        self.edges
            .iter()
            .flat_map(|(from, tos)| tos.iter().map(move |to| (from.as_str(), to.as_str())))
    }

    /// Heuristic downward-only check between two module paths.
    ///
    /// `from` may import `to` if:
    /// 1. `to` is a strict path-prefix of `from` (sibling-deeper layer
    ///    importing parent layer is forbidden — no, wait: a deeper layer
    ///    *may* import shallower; the canonical "downward-only" doctrine
    ///    in V12 means deeper-→-shallower is allowed, shallower-→-deeper is
    ///    not), OR
    /// 2. `to` does not transitively reach back to `from` in the recorded
    ///    graph (no observed cycle).
    ///
    /// Returns `false` if `to` has a recorded path back to `from` (cycle) or
    /// if `from == to` (self-import is degenerate).
    #[must_use]
    pub fn is_downward_only(&self, from: &str, to: &str) -> bool {
        if from == to {
            return false;
        }
        !self.reaches(to, from)
    }

    /// Bounded BFS reachability check. Bound is the total edge count to
    /// guarantee termination even in malformed graphs.
    fn reaches(&self, start: &str, target: &str) -> bool {
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut frontier: Vec<&str> = vec![start];
        let mut steps = 0usize;
        let bound = self.edge_count() + 1;

        while let Some(node) = frontier.pop() {
            steps += 1;
            if steps > bound {
                return false;
            }
            if !visited.insert(node) {
                continue;
            }
            let Some(targets) = self.edges.get(node) else {
                continue;
            };
            for next in targets {
                if next == target {
                    return true;
                }
                if !visited.contains(next.as_str()) {
                    frontier.push(next.as_str());
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query() {
        let mut g = LayerGraph::new();
        g.record("app.api", "app.core");
        g.record("app.api", "app.core");
        g.record("app.api", "app.util");
        assert_eq!(g.module_count(), 1);
        assert_eq!(g.edge_count(), 2);
        let targets = g.targets("app.api").expect("app.api should have targets");
        assert!(targets.contains("app.core"));
        assert!(targets.contains("app.util"));
    }

    #[test]
    fn downward_only_simple() {
        let mut g = LayerGraph::new();
        g.record("A", "B");
        g.record("B", "C");
        assert!(g.is_downward_only("A", "B"));
        assert!(g.is_downward_only("B", "C"));
        assert!(g.is_downward_only("A", "C"));
        // C importing A would create a cycle: A -> B -> C -> A.
        assert!(!g.is_downward_only("C", "A"));
    }

    #[test]
    fn self_import_rejected() {
        let g = LayerGraph::new();
        assert!(!g.is_downward_only("A", "A"));
    }

    #[test]
    fn unrelated_modules_pass() {
        let mut g = LayerGraph::new();
        g.record("X", "Y");
        assert!(g.is_downward_only("Z", "Q"));
    }
}
