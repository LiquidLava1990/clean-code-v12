//! Per-rule + pack-level tests for `cc-rules-slop`.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::comment_vs_code::CommentVsCodeRule;
use crate::defensive_pure_fn::DefensivePureFnRule;
use crate::drift_from_project::DriftFromProjectRule;
use crate::fake_thoughtful_name::FakeThoughtfulNameRule;
use crate::llm_texture::LlmTextureRule;
use crate::over_commented_obvious::OverCommentedObviousRule;
use crate::premature_abstraction::PrematureAbstractionRule;
use crate::unused_helper::UnusedHelperRule;
use crate::BuiltinSlopPack;

const SAMPLE_PATH: &str = "src/sample.rs";

fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str, language: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String(language.to_owned())),
    )
}

fn push_named_function(
    batch: &mut CpgWriteBatch,
    parent_file: NodeId,
    name: &str,
    body_range: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(body_range)),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent_file)
        .expect("edge endpoints exist");
    id
}

fn push_function_with_doc(
    batch: &mut CpgWriteBatch,
    parent_file: NodeId,
    name: &str,
    body_range: Range,
    docstring: &str,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(body_range))
            .with_prop("docstring", Value::String(docstring.to_owned())),
    );
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent_file)
        .expect("edge endpoints exist");
    id
}

fn push_child(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    kind: NodeKind,
    range_value: Range,
) -> NodeId {
    let id = batch.push_node(NodeBuilder::new(kind).with_prop("range", Value::Range(range_value)));
    batch
        .push_edge(EdgeKind::AST_PARENT, id, parent)
        .expect("edge endpoints exist");
    id
}

struct Fixture {
    batch: CpgWriteBatch,
    source: InMemorySourceTable,
    config: RuleConfig,
    project: ProjectFingerprint,
    kernel: KernelMeta,
}

impl Fixture {
    fn new() -> Self {
        Self {
            batch: CpgWriteBatch::new(),
            source: InMemorySourceTable::new(),
            config: RuleConfig::default(),
            project: ProjectFingerprint::empty(),
            kernel: KernelMeta::now(),
        }
    }

    fn with_source(self, path: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.source.insert(Utf8PathBuf::from(path), bytes);
        self
    }

    fn ctx(&self) -> RuleContext<'_> {
        RuleContext {
            batch: &self.batch,
            source: &self.source,
            config: &self.config,
            project: &self.project,
            kernel: &self.kernel,
        }
    }
}

// ---------- fake_thoughtful_name -----------------------------------------

#[test]
fn fake_thoughtful_name_flags_user_helper() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(&mut fx.batch, file, "user_helper", range(1, 1, 0, 1));
    let findings = FakeThoughtfulNameRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.fake_thoughtful_name");
}

#[test]
fn fake_thoughtful_name_silent_on_descriptive_name() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(&mut fx.batch, file, "parse_token", range(1, 1, 0, 1));
    assert!(FakeThoughtfulNameRule.run(&fx.ctx()).is_empty());
}

#[test]
fn fake_thoughtful_name_silent_in_test_files() {
    // Test fixtures intentionally use *_helper / *_handler names to
    // exercise this very rule — flagging them is rule-on-rule noise.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/tests.rs", "rust");
    push_named_function(&mut fx.batch, file, "user_helper", range(1, 1, 0, 1));
    assert!(FakeThoughtfulNameRule.run(&fx.ctx()).is_empty());
}

#[test]
fn fake_thoughtful_name_silent_on_descriptive_handler_suffix() {
    // `try_has_bare_handler` is a verb-phrase predicate ending in
    // `handler` — the prefix is descriptive, not vague.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(
        &mut fx.batch,
        file,
        "try_has_bare_handler",
        range(1, 1, 0, 1),
    );
    assert!(FakeThoughtfulNameRule.run(&fx.ctx()).is_empty());
}

#[test]
fn fake_thoughtful_name_flags_vague_verb_prefix_handler() {
    // First segment is a vague verb — still flag.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(
        &mut fx.batch,
        file,
        "process_event_handler",
        range(1, 1, 0, 1),
    );
    let findings = FakeThoughtfulNameRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

// ---------- comment_vs_code ---------------------------------------------

#[test]
fn comment_vs_code_flags_predicate_with_returns_list() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    push_function_with_doc(
        &mut fx.batch,
        file,
        "is_valid",
        range(1, 1, 0, 1),
        "Returns the list of validation errors.",
    );
    let findings = CommentVsCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.comment_vs_code");
}

#[test]
fn comment_vs_code_silent_on_aligned_doc() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    push_function_with_doc(
        &mut fx.batch,
        file,
        "is_valid",
        range(1, 1, 0, 1),
        "True iff every required field is present.",
    );
    assert!(CommentVsCodeRule.run(&fx.ctx()).is_empty());
}

// ---------- over_commented_obvious --------------------------------------

#[test]
fn over_commented_obvious_flags_restatement() {
    // Comment tokens: {increment, counter}. Code tokens: {increment, counter}.
    // Overlap = 2/2 = 100% >= 70% threshold.
    let body = "fn obvious() {\n    // increment counter\n    increment(counter);\n}\n";
    let bytes = body.as_bytes().to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(&mut fx.batch, file, "obvious", range(1, 4, 0, total));
    let findings = OverCommentedObviousRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.over_commented_obvious");
}

#[test]
fn over_commented_obvious_silent_in_test_files() {
    // Tests legitimately mirror their assertion in a comment.
    let body = "fn obvious() {\n    // increment counter\n    increment(counter);\n}\n";
    let bytes = body.as_bytes().to_vec();
    let total = bytes.len() as u32;
    let test_path = "src/tests.rs";
    let mut fx = Fixture::new().with_source(test_path, bytes);
    let file = push_file(&mut fx.batch, test_path, "rust");
    push_named_function(&mut fx.batch, file, "obvious", range(1, 4, 0, total));
    assert!(OverCommentedObviousRule.run(&fx.ctx()).is_empty());
}

#[test]
fn over_commented_obvious_silent_on_explanatory_comment() {
    let body =
        "fn meaningful() {\n    // safety: caller holds the global lock\n    write_unlocked();\n}\n";
    let bytes = body.as_bytes().to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(&mut fx.batch, file, "meaningful", range(1, 4, 0, total));
    assert!(OverCommentedObviousRule.run(&fx.ctx()).is_empty());
}

// ---------- defensive_pure_fn -------------------------------------------

#[test]
fn defensive_pure_fn_flags_try_with_no_calls() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_named_function(&mut fx.batch, file, "compute", range(1, 1, 0, 1));
    push_child(&mut fx.batch, f, NodeKind::Try, range(1, 1, 0, 1));
    let findings = DefensivePureFnRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.defensive_pure_fn");
}

#[test]
fn defensive_pure_fn_silent_when_body_makes_calls() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    let f = push_named_function(&mut fx.batch, file, "compute", range(1, 1, 0, 1));
    push_child(&mut fx.batch, f, NodeKind::Try, range(1, 1, 0, 1));
    push_child(&mut fx.batch, f, NodeKind::Call, range(1, 1, 0, 1));
    assert!(DefensivePureFnRule.run(&fx.ctx()).is_empty());
}

// ---------- unused_helper ------------------------------------------------

#[test]
fn unused_helper_flags_orphan_helper() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    let _orphan = push_named_function(&mut fx.batch, file, "user_helper", range(1, 1, 0, 1));
    // Provide call-resolution signal via an unrelated edge so the rule
    // isn't gated off the batch.
    let live = push_named_function(&mut fx.batch, file, "live", range(2, 2, 1, 2));
    let caller = push_named_function(&mut fx.batch, file, "main", range(3, 3, 2, 3));
    fx.batch
        .push_edge(EdgeKind::CG_CALLS, caller, live)
        .unwrap();
    let findings = UnusedHelperRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.unused_helper");
}

#[test]
fn unused_helper_silent_when_helper_is_called() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    let helper = push_named_function(&mut fx.batch, file, "user_helper", range(1, 1, 0, 1));
    let caller = push_named_function(&mut fx.batch, file, "caller", range(2, 2, 1, 2));
    fx.batch
        .push_edge(EdgeKind::CG_CALLS, caller, helper)
        .unwrap();
    assert!(UnusedHelperRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unused_helper_skips_when_call_resolution_unavailable() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    push_named_function(&mut fx.batch, file, "user_helper", range(1, 1, 0, 1));
    // No CG_CALLS / REFERENCES edges in batch -> rule must skip.
    assert!(UnusedHelperRule.run(&fx.ctx()).is_empty());
}

// ---------- premature_abstraction ---------------------------------------

#[test]
fn premature_abstraction_flags_single_impl_trait() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    let trait_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Greeter".into()))
            .with_prop("kind", Value::String("iface".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, trait_node, file)
        .unwrap();
    let impl_struct = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("BasicGreeter".into()))
            .with_prop("kind", Value::String("struct".into()))
            .with_prop("range", Value::Range(range(2, 2, 1, 2))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, impl_struct, file)
        .unwrap();
    fx.batch
        .push_edge(EdgeKind::CG_OVERRIDES, impl_struct, trait_node)
        .unwrap();
    let findings = PrematureAbstractionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.premature_abstraction");
}

#[test]
fn premature_abstraction_silent_on_two_impls() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "rust");
    let trait_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Greeter".into()))
            .with_prop("kind", Value::String("iface".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, trait_node, file)
        .unwrap();
    for variant in ["First", "Second"] {
        let impl_struct = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Class)
                .with_prop("name", Value::String(variant.into()))
                .with_prop("kind", Value::String("struct".into()))
                .with_prop("range", Value::Range(range(1, 1, 0, 1))),
        );
        fx.batch
            .push_edge(EdgeKind::AST_PARENT, impl_struct, file)
            .unwrap();
        fx.batch
            .push_edge(EdgeKind::CG_OVERRIDES, impl_struct, trait_node)
            .unwrap();
    }
    assert!(PrematureAbstractionRule.run(&fx.ctx()).is_empty());
}

// ---------- drift_from_project ------------------------------------------

#[test]
fn drift_from_project_flags_camel_in_snake_repo() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    // 12 snake-case functions establish the dominant.
    for i in 0..12 {
        let name = format!("snake_function_{i}");
        let id = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(name))
                .with_prop("range", Value::Range(range(1, 1, 0, 1))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    }
    // One camel-case outlier.
    let outlier = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("camelOutlierFn".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, outlier, file)
        .unwrap();
    let findings = DriftFromProjectRule.run(&fx.ctx());
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id.as_ref() == "cc.slop.drift_from_project"),
        "expected at least one drift finding, got {findings:?}"
    );
}

#[test]
fn drift_from_project_silent_on_consistent_repo() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    for i in 0..12 {
        let name = format!("snake_function_{i}");
        let id = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Function)
                .with_prop("name", Value::String(name))
                .with_prop("range", Value::Range(range(1, 1, 0, 1))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, id, file).unwrap();
    }
    assert!(DriftFromProjectRule.run(&fx.ctx()).is_empty());
}

// ---------- llm_texture --------------------------------------------------

#[test]
fn llm_texture_flags_canonical_tell_in_docstring() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    push_function_with_doc(
        &mut fx.batch,
        file,
        "process",
        range(1, 1, 0, 1),
        "Note that this function processes data. Importantly, it returns a result.",
    );
    let findings = LlmTextureRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.slop.llm_texture");
}

#[test]
fn llm_texture_silent_on_clean_docstring() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH, "python");
    push_function_with_doc(
        &mut fx.batch,
        file,
        "process",
        range(1, 1, 0, 1),
        "Parse the payload and return the canonical record.",
    );
    assert!(LlmTextureRule.run(&fx.ctx()).is_empty());
}

// ---------- pack registration ------------------------------------------

#[test]
fn builtin_slop_pack_registers_eight_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinSlopPack)
        .expect("slop pack registers without error");
    assert_eq!(reg.rules().count(), 8);
    for slug in [
        "cc.slop.comment_vs_code",
        "cc.slop.fake_thoughtful_name",
        "cc.slop.over_commented_obvious",
        "cc.slop.defensive_pure_fn",
        "cc.slop.unused_helper",
        "cc.slop.premature_abstraction",
        "cc.slop.drift_from_project",
        "cc.slop.llm_texture",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
