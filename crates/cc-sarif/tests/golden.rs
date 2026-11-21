//! Golden SARIF snapshot — regression detector for the JSON wire format.

mod common;

use cc_finding::{
    fix::{FixSafety, Range},
    ActionableMessage, Category, CostClaim, Evidence, FindingBuilder, FixProposal, Location,
    NodeId, Position, ProbeVersion, Remediation, Severity, TextEdit,
};
use cc_sarif::{to_sarif, ToolMeta};

const fn pinned_meta() -> ToolMeta {
    ToolMeta {
        name: "clean-code-v12",
        version: "0.1.0",
        information_uri: "https://github.com/LiquidLava1990/clean-code-v12",
        help_uri_prefix: "https://cleancode.dev/docs/rules",
    }
}

/// Build deterministic fixtures (no UUID drift, no `CARGO_PKG_VERSION` drift).
fn pinned_finding(
    rule: &'static str,
    sev: Severity,
    fix: Option<FixProposal>,
) -> cc_finding::Finding {
    let loc = Location {
        file: camino::Utf8PathBuf::from("src/foo.rs"),
        start: Position::new(10, 4, 120),
        end: Position::new(15, 1, 240),
        node_id: Some(NodeId::new("fn:foo::42")),
        function_qualified_name: Some("crate::foo::do_thing".to_owned()),
    };
    let evidence = Evidence {
        snippet: "fn long() { /* ... */ }".to_owned(),
        context_before: String::new(),
        context_after: String::new(),
        data_path: None,
        cpg_node_dump: None,
    };
    let msg = ActionableMessage::new(
        "function exceeds 50 LOC",
        "Long functions hide control flow and resist testing.",
        Remediation::doc_link("https://cleancode.dev/rules/fn-length"),
    );
    let mut builder = FindingBuilder::new()
        .id(cc_finding::FindingId(uuid::Uuid::nil()))
        .rule_id(rule)
        .category(Category::Shape)
        .location(loc)
        .message(msg)
        .evidence(evidence)
        .severity(sev)
        .confidence(0.9)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(ProbeVersion::new("cc-tier0", "0.1.0", 1, None))
        .kernel_version(cc_finding::KernelVersion::from_static("0.1.0-test"));
    if let Some(fp) = fix {
        builder = builder.fix(fp);
    }
    builder.build().expect("pinned finding builds")
}

#[test]
fn golden_snapshot_three_findings() {
    let edit = TextEdit {
        range: Range {
            start: Position::new(10, 4, 120),
            end: Position::new(15, 1, 240),
        },
        new_text: "fn short() {}\n".to_owned(),
    };
    let findings = vec![
        pinned_finding("cc.shape.fn_length", Severity::Blocker, None),
        pinned_finding(
            "cc.slop.duplication",
            Severity::Required,
            Some(FixProposal::Diff {
                edits: vec![edit],
                safety: FixSafety::Safe,
                confidence: 0.99,
            }),
        ),
        pinned_finding("cc.docs.missing", Severity::Nit, None),
    ];
    let doc = to_sarif(&findings, pinned_meta());
    let json = serde_json::to_string_pretty(&doc).expect("serialise");

    insta::assert_snapshot!("sarif_three_findings", json);
}
