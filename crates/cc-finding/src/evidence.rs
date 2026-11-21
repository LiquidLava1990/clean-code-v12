//! Human-review evidence attached to a Finding.

use serde::{Deserialize, Serialize};

use crate::location::Location;

/// A single step in a taint dataflow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowStep {
    /// Where in the code this step occurs.
    pub location: Location,
    /// Human-readable description of what happens at this step.
    pub note: String,
}

/// Ordered sequence of dataflow steps, from source to sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFlowPath {
    /// Steps in source-to-sink order.
    pub steps: Vec<DataFlowStep>,
}

/// Human-reviewable evidence around a Finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Pre-trimmed source window for display (the offending region).
    pub snippet: String,
    /// Up-to-3 lines preceding [`Self::snippet`].
    pub context_before: String,
    /// Up-to-3 lines following [`Self::snippet`].
    pub context_after: String,
    /// Optional dataflow trace (for taint findings).
    pub data_path: Option<DataFlowPath>,
    /// CPG node dump (debug aid; only emitted under `--verbose`).
    pub cpg_node_dump: Option<String>,
}

impl Evidence {
    /// Construct evidence with empty context and no dataflow path.
    #[must_use]
    pub fn from_snippet(snippet: impl Into<String>) -> Self {
        Self {
            snippet: snippet.into(),
            context_before: String::new(),
            context_after: String::new(),
            data_path: None,
            cpg_node_dump: None,
        }
    }
}
