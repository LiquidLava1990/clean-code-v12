//! Test fixtures shared between integration tests.
#![allow(
    dead_code,
    missing_docs,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn
)]

use camino::Utf8PathBuf;
use cc_finding::{
    ActionableMessage, Category, CostClaim, Evidence, Finding, FindingBuilder, Location, NodeId,
    Position, ProbeVersion, Remediation, Severity,
};

#[must_use]
pub fn sample_location() -> Location {
    Location {
        file: Utf8PathBuf::from("src/foo.rs"),
        start: Position::new(10, 4, 120),
        end: Position::new(15, 1, 240),
        node_id: Some(NodeId::new("fn:foo::42")),
        function_qualified_name: Some("crate::foo::do_thing".to_owned()),
    }
}

#[must_use]
pub fn sample_message() -> ActionableMessage {
    ActionableMessage::new(
        "function exceeds 50 LOC",
        "Long functions hide control flow and resist testing; \
         extract by responsibility, not by size.",
        Remediation::doc_link("https://cleancode.dev/rules/fn-length"),
    )
}

#[must_use]
pub fn sample_evidence(snippet: &str) -> Evidence {
    Evidence {
        snippet: snippet.to_owned(),
        context_before: "// before\nfn caller() {".to_owned(),
        context_after: "}\n// after".to_owned(),
        data_path: None,
        cpg_node_dump: None,
    }
}

#[must_use]
pub fn sample_probe_version() -> ProbeVersion {
    ProbeVersion::new("cc-tier0", "0.1.0", 1, None)
}

#[must_use]
pub fn sample_finding(snippet: &str) -> Finding {
    FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence(snippet))
        .severity(Severity::Required)
        .confidence(0.92)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(sample_probe_version())
        .build()
        .expect("sample finding builds")
}

#[must_use]
pub fn sample_finding_with_node(snippet: &str, node: &str) -> Finding {
    let mut loc = sample_location();
    loc.node_id = Some(NodeId::new(node));
    FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(loc)
        .message(sample_message())
        .evidence(sample_evidence(snippet))
        .severity(Severity::Required)
        .confidence(0.92)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(sample_probe_version())
        .build()
        .expect("sample finding builds")
}
