//! Shared test fixtures for `cc-rdformat`'s in-tree tests.
//!
//! Kept as a `#[cfg(test)]` module so it never ships in the public API.

#![allow(missing_docs)]

use camino::Utf8PathBuf;

use cc_finding::{
    ActionableMessage, Category, CostClaim, Evidence, Finding, FindingBuilder, FixProposal,
    FixSafety, Location, Position, ProbeVersion, Range, Remediation, Severity, TextEdit,
};

pub fn sample_location(path: &str) -> Location {
    Location {
        file: Utf8PathBuf::from(path),
        start: Position::new(10, 5, 100),
        end: Position::new(10, 25, 120),
        node_id: None,
        function_qualified_name: Some("crate::module::offender".to_owned()),
    }
}

pub fn sample_finding(rule_id: &'static str, severity: Severity) -> Finding {
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Shape)
        .location(sample_location("src/lib.rs"))
        .message(ActionableMessage::new(
            "function exceeds 50 lines",
            "Long functions are hard to test and review.",
            Remediation::doc_link("https://example.org/fn_length"),
        ))
        .evidence(Evidence::from_snippet("fn long() { /* ... */ }"))
        .severity(severity)
        .confidence(1.0)
        .cost(CostClaim::BlockingDebt { weight: 5 })
        .probe_version(ProbeVersion::new("cc-tier0", "1.0.0", 1, None))
        .build()
        .expect("test fixture must build")
}

pub fn safe_diff_fix() -> FixProposal {
    FixProposal::Diff {
        edits: vec![
            TextEdit {
                range: Range {
                    start: Position::new(10, 5, 100),
                    end: Position::new(10, 25, 120),
                },
                new_text: "renamed_fn".to_owned(),
            },
            TextEdit {
                range: Range {
                    start: Position::new(11, 1, 130),
                    end: Position::new(11, 1, 130),
                },
                new_text: "// note\n".to_owned(),
            },
        ],
        safety: FixSafety::Safe,
        confidence: 0.99,
    }
}

pub fn unsafe_diff_fix() -> FixProposal {
    FixProposal::Diff {
        edits: vec![TextEdit {
            range: Range {
                start: Position::new(10, 5, 100),
                end: Position::new(10, 25, 120),
            },
            new_text: "behavioural_change".to_owned(),
        }],
        safety: FixSafety::Unsafe,
        confidence: 0.7,
    }
}

pub fn llm_rewrite_fix() -> FixProposal {
    FixProposal::LlmRewrite {
        original: "fn long() {}".to_owned(),
        proposed: "fn short() {}".to_owned(),
        rationale: "shorter is better".to_owned(),
        prompt_hash: cc_finding::PromptHash("0".repeat(64)),
    }
}

pub fn finding_with_fix(severity: Severity, fix: FixProposal) -> Finding {
    let mut f = sample_finding("cc.shape.fn_length", severity);
    f.fix = Some(fix);
    f
}
