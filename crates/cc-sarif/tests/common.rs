//! Test fixtures shared between cc-sarif integration tests.
#![allow(
    dead_code,
    missing_docs,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn
)]

use camino::Utf8PathBuf;
use cc_finding::{
    fix::{FixSafety, PromptHash, Range},
    ActionableMessage, Category, CodemodEngine, CodemodScope, CostClaim, Evidence, Finding,
    FindingBuilder, FixProposal, Location, NodeId, Position, ProbeVersion, Remediation, Severity,
    TextEdit,
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
pub fn finding_with(rule_id: &'static str, sev: Severity) -> Finding {
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("fn long() { /* ... */ }"))
        .severity(sev)
        .confidence(0.92)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(sample_probe_version())
        .build()
        .expect("builder produces a valid finding")
}

#[must_use]
pub fn finding_with_diff_fix() -> Finding {
    let edit = TextEdit {
        range: Range {
            start: Position::new(10, 4, 120),
            end: Position::new(15, 1, 240),
        },
        new_text: "fn short() { ok() }\n".to_owned(),
    };
    FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("fn long() { /* ... */ }"))
        .severity(Severity::Required)
        .confidence(0.95)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(sample_probe_version())
        .fix(FixProposal::Diff {
            edits: vec![edit],
            safety: FixSafety::Safe,
            confidence: 0.99,
        })
        .build()
        .expect("builder produces a valid finding")
}

#[must_use]
pub fn finding_with_codemod_fix() -> Finding {
    FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("fn long() { /* ... */ }"))
        .severity(Severity::Required)
        .confidence(0.95)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(sample_probe_version())
        .fix(FixProposal::Codemod {
            engine: CodemodEngine::AstGrep,
            pattern: "fn long() { $$$ }".to_owned(),
            replacement: "fn short() { ok() }".to_owned(),
            scope: CodemodScope::Function,
        })
        .build()
        .expect("builder produces a valid finding")
}

#[must_use]
pub fn finding_with_llm_rewrite() -> Finding {
    FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("fn long() { /* ... */ }"))
        .severity(Severity::Required)
        .confidence(0.85)
        .cost(CostClaim::BlockingDebt { weight: 3 })
        .probe_version(sample_probe_version())
        .fix(FixProposal::LlmRewrite {
            original: "fn long() { /* ... */ }".to_owned(),
            proposed: "fn short() { ok() }".to_owned(),
            rationale: "extract sub-step into helper".to_owned(),
            prompt_hash: PromptHash("a1b2c3d4".to_owned()),
        })
        .build()
        .expect("builder produces a valid finding")
}
