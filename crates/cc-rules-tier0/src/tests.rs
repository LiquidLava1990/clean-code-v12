//! Per-rule unit tests + a registry integration test.
//!
//! Each rule has at least one positive (violating) and one negative
//! (clean) case. Test fixtures build a `CpgWriteBatch` by hand using
//! `NodeBuilder` + `push_node` / `push_edge`.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::error::bare::BareCatchRule;
use crate::error::broad_catch::BroadCatchRule;
use crate::error::no_action::NoActionRule;
use crate::meta::new_file_clean::NewFileCleanRule;
use crate::meta::refactor_drift::RefactorDriftRule;
use crate::shape::boolean_complexity::BooleanComplexityRule;
use crate::shape::cognitive::CognitiveRule;
use crate::shape::cyclomatic::CyclomaticRule;
use crate::shape::dead_code::DeadCodeRule;
use crate::shape::duplication::DuplicationRule;
use crate::shape::expression_depth::ExpressionDepthRule;
use crate::shape::file_length::FileLengthRule;
use crate::shape::fn_length::FnLengthRule;
use crate::shape::god_struct::GodStructRule;
use crate::shape::identifier_entropy::IdentifierEntropyRule;
use crate::shape::lambda_complexity::LambdaComplexityRule;
use crate::shape::local_var_count::LocalVarCountRule;
use crate::shape::naming_drift::NamingDriftRule;
use crate::shape::nesting_depth::NestingDepthRule;
use crate::shape::nesting_early_return::NestingEarlyReturnRule;
use crate::shape::no_inheritance::NoInheritanceRule;
use crate::shape::param_count::ParamCountRule;
use crate::shape::public_surface_size::PublicSurfaceSizeRule;
use crate::shape::return_count::ReturnCountRule;
use crate::shape::statement_count::StatementCountRule;
use crate::shape::swallowed_with_log::SwallowedWithLogRule;
use crate::type_coverage::coverage::TypeCoverageRule;
use crate::BuiltinTier0Pack;

// ---------- shared fixtures -----------------------------------------------

const SAMPLE_PATH: &str = "src/sample.rs";

fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("rust".into())),
    )
}

fn push_function(
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

fn push_child(batch: &mut CpgWriteBatch, parent: NodeId, kind: NodeKind, range: Range) -> NodeId {
    let id = batch.push_node(NodeBuilder::new(kind).with_prop("range", Value::Range(range)));
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

// ---------- fn_length -----------------------------------------------------

#[test]
fn fn_length_flags_long_function() {
    // 90 logical lines of body content => violates threshold of 80.
    let body: String = (0..90).map(|i| format!("let v{i} = {i};\n")).collect();
    let bytes = body.into_bytes();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "long_fn", range(1, 90, 0, total));
    let findings = FnLengthRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.fn_length");
}

#[test]
fn fn_length_silent_on_short_function() {
    let bytes = b"let x = 1;\nlet y = 2;\n".to_vec();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "short_fn", range(1, 2, 0, total));
    assert!(FnLengthRule.run(&fx.ctx()).is_empty());
}

// ---------- file_length ---------------------------------------------------

#[test]
fn file_length_flags_god_file() {
    let body: String = (0..1600).map(|i| format!("line {i}\n")).collect();
    let bytes = body.into_bytes();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    let findings = FileLengthRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.file_length");
}

#[test]
fn file_length_silent_on_small_file() {
    let bytes = b"let x = 1;\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    push_file(&mut fx.batch, SAMPLE_PATH);
    assert!(FileLengthRule.run(&fx.ctx()).is_empty());
}

// ---------- nesting_depth -------------------------------------------------

#[test]
fn nesting_depth_flags_deep_nest() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "nested", range(1, 1, 0, 1));
    // 4 nested branches => depth 4 > 3.
    let mut current = f;
    for _ in 0..4 {
        current = push_child(&mut fx.batch, current, NodeKind::Branch, range(1, 1, 0, 1));
    }
    let findings = NestingDepthRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.nesting_depth");
}

#[test]
fn nesting_depth_silent_on_shallow_nest() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "shallow", range(1, 1, 0, 1));
    let b1 = push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    let b2 = push_child(&mut fx.batch, b1, NodeKind::Loop, range(1, 1, 0, 1));
    let _b3 = push_child(&mut fx.batch, b2, NodeKind::Try, range(1, 1, 0, 1));
    assert!(NestingDepthRule.run(&fx.ctx()).is_empty());
}

// ---------- param_count ---------------------------------------------------

#[test]
fn param_count_flags_too_many_positionals() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "wide", range(1, 1, 0, 1));
    for i in 0..6 {
        let p = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Parameter).with_prop("name", Value::String(format!("p{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    }
    let findings = ParamCountRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn param_count_silent_when_under_threshold() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "narrow", range(1, 1, 0, 1));
    for i in 0..3 {
        let p = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Parameter).with_prop("name", Value::String(format!("p{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    }
    assert!(ParamCountRule.run(&fx.ctx()).is_empty());
}

#[test]
fn param_count_skips_self_and_keyword_only() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "method", range(1, 1, 0, 1));
    // self + 5 positional + 2 kw-only = 6 positional after `self` filter? No:
    // 5 positional (under threshold 5) + self + kw_only ⇒ silent.
    let self_p = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Parameter).with_prop("name", Value::String("self".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, self_p, f).unwrap();
    for i in 0..5 {
        let p = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Parameter).with_prop("name", Value::String(format!("p{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    }
    for i in 0..2 {
        let p = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Parameter)
                .with_prop("name", Value::String(format!("kw{i}")))
                .with_prop("is_keyword_only", Value::Bool(true)),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    }
    assert!(ParamCountRule.run(&fx.ctx()).is_empty());
}

// ---------- cyclomatic ----------------------------------------------------

#[test]
fn cyclomatic_flags_high_branch_count() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "branchy", range(1, 1, 0, 1));
    for _ in 0..11 {
        push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    }
    let findings = CyclomaticRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn cyclomatic_silent_on_simple_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "simple", range(1, 1, 0, 1));
    push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    assert!(CyclomaticRule.run(&fx.ctx()).is_empty());
}

// ---------- cognitive -----------------------------------------------------

#[test]
fn cognitive_flags_deeply_nested_branches() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "complex", range(1, 1, 0, 1));
    // Build a chain: f -> branch -> branch -> branch -> branch -> branch -> branch
    // Cognitive = 1 + 2 + 3 + 4 + 5 + 6 = 21 > 15.
    let mut current = f;
    for _ in 0..6 {
        current = push_child(&mut fx.batch, current, NodeKind::Branch, range(1, 1, 0, 1));
    }
    let findings = CognitiveRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
}

#[test]
fn cognitive_silent_on_flat_branches() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "flat", range(1, 1, 0, 1));
    for _ in 0..5 {
        push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    }
    // Each adds 1 (nesting 0) ⇒ score 5, under threshold 15.
    assert!(CognitiveRule.run(&fx.ctx()).is_empty());
}

// ---------- no_inheritance ------------------------------------------------

#[test]
fn no_inheritance_flags_extending_class() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("Sub".into()))
            .with_prop("extends", Value::String("Super".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    let findings = NoInheritanceRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.no_inheritance");
}

#[test]
fn no_inheritance_silent_on_standalone_class() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("Lone".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    assert!(NoInheritanceRule.run(&fx.ctx()).is_empty());
}

// ---------- bare_catch ----------------------------------------------------

#[test]
fn bare_catch_flags_handler_without_type() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(NodeBuilder::new(NodeKind::Block));
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    let findings = BareCatchRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.error.bare");
}

#[test]
fn bare_catch_silent_on_typed_handler() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block)
            .with_prop("exception_type", Value::String("ValueError".into())),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(BareCatchRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_catch_silent_on_broad_typed_handler() {
    // `except Exception:` is broad-but-typed — owned by
    // `cc.error.broad_catch` (Required), not `cc.error.bare` (Blocker).
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block)
            .with_prop("exception_type", Value::String("Exception".into())),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(BareCatchRule.run(&fx.ctx()).is_empty());
}

#[test]
fn bare_catch_flags_rust_wildcard() {
    // `_` is a Rust catch-all wildcard — truly bare, fires.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block).with_prop("exception_type", Value::String("_".into())),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert_eq!(BareCatchRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn broad_catch_flags_exception_type() {
    // `except Exception:` without re-raise => broad_catch fires.
    let body = b"try { do_thing(); } catch (Exception e) { log.error(e); }".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block)
            .with_prop("exception_type", Value::String("Exception".into()))
            .with_prop("range", Value::Range(range(1, 1, 25, 55))),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 60)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    let findings = BroadCatchRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.error.broad_catch");
}

#[test]
fn broad_catch_silent_when_handler_reraises() {
    // `except Exception: log; raise` => re-raises, do not fire.
    let body =
        b"try:\n    do_thing()\nexcept Exception:\n    log.error(\"x\")\n    raise\n".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let total = 67u32;
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block)
            .with_prop("exception_type", Value::String("Exception".into()))
            .with_prop("range", Value::Range(range(1, 5, 18, total))),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 5, 0, total)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(BroadCatchRule.run(&fx.ctx()).is_empty());
}

#[test]
fn broad_catch_silent_on_narrow_handler() {
    // `except ValueError:` is narrow — broad_catch never fires.
    let body = b"try { x() } catch (ValueError e) { recover(); }".to_vec();
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block)
            .with_prop("exception_type", Value::String("ValueError".into()))
            .with_prop("range", Value::Range(range(1, 1, 12, 47))),
    );
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(range(1, 1, 0, 47)))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(BroadCatchRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_all_tier0_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTier0Pack)
        .expect("Tier-0 pack registers without error");
    assert_eq!(reg.rules().count(), 27);
    for slug in [
        "cc.shape.fn_length",
        "cc.shape.file_length",
        "cc.shape.nesting_depth",
        "cc.shape.param_count",
        "cc.shape.cyclomatic",
        "cc.shape.cognitive",
        "cc.shape.no_inheritance",
        "cc.error.bare",
        "cc.error.broad_catch",
        "cc.shape.duplication",
        "cc.shape.dead_code",
        "cc.type.coverage",
        "cc.shape.naming_drift",
        "cc.shape.nesting_early_return",
        "cc.error.no_action",
        "cc.meta.refactor_drift",
        "cc.meta.new_file_clean",
        // Phase-7 Tier-0 forever-rule gap fills.
        "cc.shape.return_count",
        "cc.shape.boolean_complexity",
        "cc.shape.local_var_count",
        "cc.shape.statement_count",
        "cc.shape.identifier_entropy",
        "cc.shape.lambda_complexity",
        "cc.shape.public_surface_size",
        "cc.shape.god_struct",
        "cc.shape.expression_depth",
        "cc.shape.swallowed_with_log_no_recovery",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

// ---------- duplication ---------------------------------------------------

fn long_identical_body() -> String {
    let mut s = String::new();
    for i in 0..40 {
        s.push_str(&format!(
            "let alpha_token_{i} = compute_value(arg_{i}, helper_arg_{i});\n"
        ));
    }
    s
}

#[test]
fn duplication_flags_two_copy_pasted_functions() {
    let body = long_identical_body();
    let bytes = format!("{body}{body}").into_bytes();
    let body_len = body.len() as u32;
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "alpha", range(1, 40, 0, body_len));
    push_function(&mut fx.batch, file, "beta", range(41, 80, body_len, total));
    let findings = DuplicationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "expected exactly one paired finding");
    assert_eq!(findings[0].rule_id, "cc.shape.duplication");
    assert_eq!(findings[0].related.len(), 1);
}

#[test]
fn duplication_silent_in_test_files() {
    // Test files legitimately repeat setup boilerplate across cases.
    // Identical bodies in `crates/foo/src/tests.rs` must NOT fire — same
    // logic would have flagged ~74 self-host findings on cc-rules-tier0
    // alone before this guard landed.
    let test_path = "crates/foo/src/tests.rs";
    let body = long_identical_body();
    let bytes = format!("{body}{body}").into_bytes();
    let body_len = body.len() as u32;
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(test_path, bytes);
    let file = push_file(&mut fx.batch, test_path);
    push_function(&mut fx.batch, file, "alpha", range(1, 40, 0, body_len));
    push_function(&mut fx.batch, file, "beta", range(41, 80, body_len, total));
    assert!(
        DuplicationRule.run(&fx.ctx()).is_empty(),
        "duplication rule must skip test files"
    );
}

#[test]
fn duplication_silent_on_distinct_bodies() {
    let body_a: String = (0..40)
        .map(|i| format!("let unique_left_{i} = first_helper({i});\n"))
        .collect();
    let body_b: String = (0..40)
        .map(|i| format!("emit_event_into_bus(\"channel\", payload_{i});\n"))
        .collect();
    let split = body_a.len() as u32;
    let bytes = format!("{body_a}{body_b}").into_bytes();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "left", range(1, 40, 0, split));
    push_function(&mut fx.batch, file, "right", range(41, 80, split, total));
    assert!(DuplicationRule.run(&fx.ctx()).is_empty());
}

/// Build a dispatch-style match-arm function body with the given name +
/// arm count. Each arm delegates a string node-kind to a `Some(handler)`
/// call. This is the structural shape that produced 3 of the 14
/// self-host findings in 2026-04 (cc-frontend-rust dispatch_*).
fn dispatch_match_body(fn_name: &str, arms: usize) -> String {
    let mut s = format!(
        "fn {fn_name}(ctx: &mut LiftCtx, store: &mut Batch, node: TsNode, parent: NodeId) -> Option<NodeId> {{\n    match node.kind() {{\n"
    );
    for i in 0..arms {
        s.push_str(&format!(
            "        \"node_kind_{i}\" => Some(handler_{i}(ctx, store, node, parent)),\n"
        ));
    }
    s.push_str("        _ => None,\n    }\n}\n");
    s
}

#[test]
fn duplication_silent_on_dispatch_match_arm_shape() {
    // Pure dispatch-style match-arm functions: each arm maps a node-kind
    // string to a single delegated function call. Architectures across
    // language frontends repeat this shape on purpose (one dispatch_*
    // per node-kind family). SimHash cross-correlates the boilerplate
    // because the distinguishing tokens (the kind strings + handler
    // names) are heavily out-numbered by the structural skeleton.
    //
    // Heuristic: when a function body is dominated by `=>` arm-tokens
    // (each `=>` + an identifier handler call counts as ~5-8 tokens of
    // dispatch glue), the rule skips it. The two functions below share
    // the same signature + match skeleton + arm count, which is exactly
    // the SimHash false-positive shape we observed on self-host.
    let body_a = dispatch_match_body("dispatch_item", 8);
    let body_b = dispatch_match_body("dispatch_control", 8);
    let split = body_a.len() as u32;
    let bytes = format!("{body_a}{body_b}").into_bytes();
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "dispatch_item", range(1, 14, 0, split));
    push_function(
        &mut fx.batch,
        file,
        "dispatch_control",
        range(15, 28, split, total),
    );

    // Pre-condition: without the heuristic, this fixture flags. We assert
    // the heuristic OFF behaviour by first verifying the shingle index
    // would otherwise pair them — the regression-positive test above
    // already proves the rule fires on real copy-paste, so here we only
    // assert the dispatch-shape skip path.
    let findings = DuplicationRule.run(&fx.ctx());
    assert!(
        findings.is_empty(),
        "dispatch-shape match-arm functions must be skipped; got {findings:?}"
    );
}

#[test]
fn duplication_still_flags_real_copy_paste_after_dispatch_heuristic() {
    // Regression guard: the dispatch-skip heuristic from the test above
    // must NOT swallow genuine copy-paste. Two functions whose bodies
    // are imperative statement sequences (no `match`, no `=>`) must
    // still produce exactly one duplication finding.
    let body = long_identical_body();
    let bytes = format!("{body}{body}").into_bytes();
    let body_len = body.len() as u32;
    let total = bytes.len() as u32;
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, bytes);
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "alpha", range(1, 40, 0, body_len));
    push_function(&mut fx.batch, file, "beta", range(41, 80, body_len, total));
    let findings = DuplicationRule.run(&fx.ctx());
    assert_eq!(
        findings.len(),
        1,
        "non-dispatch copy-paste must still be flagged after the heuristic"
    );
    assert_eq!(findings[0].rule_id, "cc.shape.duplication");
}

// ---------- dead_code -----------------------------------------------------

#[test]
fn dead_code_flags_unreferenced_top_level_function() {
    // Rule needs at least one CG_CALLS/REFERENCES/CG_OVERRIDES edge in the
    // batch to consider call-resolution "available". Build two functions
    // with one referencing the other so the resolution-signal is present;
    // `lonely_helper` itself remains unreferenced and must be flagged.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let lonely = push_function(&mut fx.batch, file, "lonely_helper", range(1, 1, 0, 1));
    let live_target = push_function(&mut fx.batch, file, "live_target", range(2, 2, 1, 2));
    let pub_caller = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("entry".into()))
            .with_prop("is_pub", Value::Bool(true)),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, pub_caller, file)
        .unwrap();
    fx.batch
        .push_edge(EdgeKind::CG_CALLS, pub_caller, live_target)
        .unwrap();
    let findings = DeadCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.shape.dead_code");
    assert!(findings[0].message.headline.contains("lonely_helper"));
    let _unused_in_test = lonely;
}

#[test]
fn dead_code_silent_when_call_resolution_unavailable() {
    // No CG_CALLS / REFERENCES / CG_OVERRIDES edges in the batch — the
    // frontend hasn't done call resolution, so the rule has no signal
    // and must skip rather than emit a finding for every top-level fn.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "lonely_helper", range(1, 1, 0, 1));
    push_function(&mut fx.batch, file, "another_helper", range(2, 2, 1, 2));
    let findings = DeadCodeRule.run(&fx.ctx());
    assert!(
        findings.is_empty(),
        "expected no findings, got {findings:?}"
    );
}

#[test]
fn dead_code_silent_on_referenced_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let target = push_function(&mut fx.batch, file, "called_helper", range(1, 1, 0, 1));
    let caller = push_function(&mut fx.batch, file, "caller", range(2, 2, 1, 2));
    fx.batch
        .push_edge(EdgeKind::CG_CALLS, caller, target)
        .unwrap();
    // `caller` is itself top-level and unreferenced; mark it pub to exempt.
    let pub_caller = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("entry".into()))
            .with_prop("is_pub", Value::Bool(true)),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, pub_caller, file)
        .unwrap();
    fx.batch
        .push_edge(EdgeKind::CG_CALLS, pub_caller, caller)
        .unwrap();
    let findings = DeadCodeRule.run(&fx.ctx());
    // Only `target` is dead? No — `target` has a CG_CALLS edge in,
    // `caller` has one in, `pub_caller` is pub-exempt ⇒ all clean.
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn dead_code_skips_main_and_dunders() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "main", range(1, 1, 0, 1));
    push_function(&mut fx.batch, file, "__init__", range(2, 2, 1, 2));
    push_function(&mut fx.batch, file, "test_something", range(3, 3, 2, 3));
    assert!(DeadCodeRule.run(&fx.ctx()).is_empty());
}

// ---------- type_coverage -------------------------------------------------

fn push_python_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("python".into())),
    )
}

#[test]
fn type_coverage_flags_untyped_python_function() {
    let mut fx = Fixture::new();
    let file = push_python_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "process", range(1, 1, 0, 1));
    let p = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Parameter).with_prop("name", Value::String("payload".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    let findings = TypeCoverageRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.type.coverage");
}

#[test]
fn type_coverage_silent_on_fully_annotated_python_function() {
    let mut fx = Fixture::new();
    let file = push_python_file(&mut fx.batch, SAMPLE_PATH);
    let f = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("process".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1)))
            .with_prop("return_type", Value::String("dict".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, f, file).unwrap();
    let p = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Parameter)
            .with_prop("name", Value::String("payload".into()))
            .with_prop("type", Value::String("bytes".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, p, f).unwrap();
    assert!(TypeCoverageRule.run(&fx.ctx()).is_empty());
}

#[test]
fn type_coverage_silent_on_rust_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let _f = push_function(&mut fx.batch, file, "untyped", range(1, 1, 0, 1));
    assert!(TypeCoverageRule.run(&fx.ctx()).is_empty());
}

// ---------- naming_drift --------------------------------------------------

#[test]
fn naming_drift_flags_camel_case_in_python() {
    let mut fx = Fixture::new();
    let file = push_python_file(&mut fx.batch, SAMPLE_PATH);
    let f = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("processPayload".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, f, file).unwrap();
    let findings = NamingDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.naming_drift");
}

#[test]
fn naming_drift_silent_on_snake_case_in_python() {
    let mut fx = Fixture::new();
    let file = push_python_file(&mut fx.batch, SAMPLE_PATH);
    let f = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String("process_payload".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, f, file).unwrap();
    assert!(NamingDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- nesting_early_return -----------------------------------------

#[test]
fn nesting_early_return_flags_nested_branch() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "deep", range(1, 1, 0, 1));
    let outer = push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    let _inner = push_child(&mut fx.batch, outer, NodeKind::Branch, range(1, 1, 0, 1));
    let findings = NestingEarlyReturnRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.nesting_early_return");
}

#[test]
fn nesting_early_return_silent_on_flat_branch() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let f = push_function(&mut fx.batch, file, "flat", range(1, 1, 0, 1));
    let _b = push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    assert!(NestingEarlyReturnRule.run(&fx.ctx()).is_empty());
}

// ---------- no_action -----------------------------------------------------

#[test]
fn no_action_flags_short_actionless_message() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("raise".into()))
            .with_prop("message", Value::String("error".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let findings = NoActionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.error.no_action");
}

#[test]
fn no_action_silent_on_actionable_message() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let call = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("name", Value::String("raise".into()))
            .with_prop(
                "message",
                Value::String("missing API key — set ANTHROPIC_API_KEY env var".into()),
            )
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    assert!(NoActionRule.run(&fx.ctx()).is_empty());
}

// ---------- meta stubs ----------------------------------------------------

#[test]
fn refactor_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(RefactorDriftRule.run(&fx.ctx()).is_empty());
}

#[test]
fn new_file_clean_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(NewFileCleanRule.run(&fx.ctx()).is_empty());
}

// ---------- return_count -------------------------------------------------

#[test]
fn return_count_flags_function_with_too_many_returns() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "branchy", range(1, 1, 0, 1));
    for _ in 0..7 {
        push_child(&mut fx.batch, f, NodeKind::Return, range(1, 1, 0, 1));
    }
    let findings = ReturnCountRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.return_count");
}

#[test]
fn return_count_silent_on_few_returns() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "calm", range(1, 1, 0, 1));
    for _ in 0..3 {
        push_child(&mut fx.batch, f, NodeKind::Return, range(1, 1, 0, 1));
    }
    assert!(ReturnCountRule.run(&fx.ctx()).is_empty());
}

#[test]
fn return_count_does_not_count_returns_in_nested_function() {
    // Outer fn has 4 returns. A nested closure adds 5 more returns; those
    // must not bleed into the outer count (outer total stays at 4).
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let outer = push_function(&mut fx.batch, file, "outer", range(1, 1, 0, 1));
    for _ in 0..4 {
        push_child(&mut fx.batch, outer, NodeKind::Return, range(1, 1, 0, 1));
    }
    let inner = push_child(&mut fx.batch, outer, NodeKind::Function, range(1, 1, 0, 1));
    for _ in 0..5 {
        push_child(&mut fx.batch, inner, NodeKind::Return, range(1, 1, 0, 1));
    }
    assert!(ReturnCountRule.run(&fx.ctx()).is_empty());
}

// ---------- boolean_complexity ------------------------------------------

#[test]
fn boolean_complexity_flags_long_chain_in_rust_function() {
    let body = b"if a && b && c && d && e && f { return 1; }".to_vec();
    let total = body.len() as u32;
    let mut fx = Fixture::new().with_source("src/prod.rs", body);
    let file = push_file(&mut fx.batch, "src/prod.rs");
    push_function(&mut fx.batch, file, "wide", range(1, 1, 0, total));
    let findings = BooleanComplexityRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.boolean_complexity");
}

#[test]
fn boolean_complexity_silent_under_threshold() {
    let body = b"if a && b && c { return 1; }".to_vec();
    let total = body.len() as u32;
    let mut fx = Fixture::new().with_source("src/prod.rs", body);
    let file = push_file(&mut fx.batch, "src/prod.rs");
    push_function(&mut fx.batch, file, "narrow", range(1, 1, 0, total));
    assert!(BooleanComplexityRule.run(&fx.ctx()).is_empty());
}

#[test]
fn boolean_complexity_silent_when_split_across_lines() {
    // 6 operands across two lines (3 + 2), neither line exceeds threshold.
    let body = b"if a && b && c\n    && d && e {}\n".to_vec();
    let total = body.len() as u32;
    let mut fx = Fixture::new().with_source("src/prod.rs", body);
    let file = push_file(&mut fx.batch, "src/prod.rs");
    push_function(&mut fx.batch, file, "split", range(1, 2, 0, total));
    assert!(BooleanComplexityRule.run(&fx.ctx()).is_empty());
}

// ---------- local_var_count ----------------------------------------------

#[test]
fn local_var_count_flags_too_many_distinct_locals() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "wide", range(1, 1, 0, 1));
    for i in 0..16 {
        let v = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String(format!("v{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, v, f).unwrap();
    }
    let findings = LocalVarCountRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.local_var_count");
}

#[test]
fn local_var_count_silent_under_threshold() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "narrow", range(1, 1, 0, 1));
    for i in 0..10 {
        let v = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String(format!("v{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, v, f).unwrap();
    }
    assert!(LocalVarCountRule.run(&fx.ctx()).is_empty());
}

#[test]
fn local_var_count_dedupes_repeated_names() {
    // Same variable name reassigned 30 times = 1 distinct local. Silent.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "loop_var", range(1, 1, 0, 1));
    for _ in 0..30 {
        let v = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String("acc".into())),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, v, f).unwrap();
    }
    assert!(LocalVarCountRule.run(&fx.ctx()).is_empty());
}

// ---------- statement_count ----------------------------------------------

#[test]
fn statement_count_flags_long_function_body() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "long", range(1, 1, 0, 1));
    for _ in 0..51 {
        push_child(&mut fx.batch, f, NodeKind::Call, range(1, 1, 0, 1));
    }
    let findings = StatementCountRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.statement_count");
}

#[test]
fn statement_count_silent_on_short_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "short", range(1, 1, 0, 1));
    for _ in 0..10 {
        push_child(&mut fx.batch, f, NodeKind::Call, range(1, 1, 0, 1));
    }
    assert!(StatementCountRule.run(&fx.ctx()).is_empty());
}

// ---------- identifier_entropy -------------------------------------------

#[test]
fn identifier_entropy_flags_low_entropy_long_name() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let v = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String("aaaaaa".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, v, file).unwrap();
    let findings = IdentifierEntropyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.identifier_entropy");
}

#[test]
fn identifier_entropy_silent_on_short_name() {
    // `id` is short — exempted by length floor regardless of entropy.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let v = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable).with_prop("name", Value::String("id".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, v, file).unwrap();
    assert!(IdentifierEntropyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn identifier_entropy_silent_on_normal_name() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let v = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String("pending_invoices".into())),
    );
    fx.batch.push_edge(EdgeKind::AST_PARENT, v, file).unwrap();
    assert!(IdentifierEntropyRule.run(&fx.ctx()).is_empty());
}

// ---------- lambda_complexity --------------------------------------------

#[test]
fn lambda_complexity_flags_high_branch_lambda() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    // Lambda assigned into a Call argument context — frontends sometimes
    // mark it via `is_lambda`; we use that explicit signal here.
    let call = fx.batch.push_node(NodeBuilder::new(NodeKind::Call));
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, call, file)
        .unwrap();
    let lambda = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("is_lambda", Value::Bool(true))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, lambda, call)
        .unwrap();
    for _ in 0..5 {
        push_child(&mut fx.batch, lambda, NodeKind::Branch, range(1, 1, 0, 1));
    }
    let findings = LambdaComplexityRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.lambda_complexity");
}

#[test]
fn lambda_complexity_silent_on_top_level_function() {
    // A top-level Function is not a lambda; this rule does not fire on it
    // even when its branch count is high (R-CYC owns that case).
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let f = push_function(&mut fx.batch, file, "top_level", range(1, 1, 0, 1));
    for _ in 0..10 {
        push_child(&mut fx.batch, f, NodeKind::Branch, range(1, 1, 0, 1));
    }
    assert!(LambdaComplexityRule.run(&fx.ctx()).is_empty());
}

#[test]
fn lambda_complexity_silent_on_named_method_inside_block() {
    // Methods inside Rust `impl` blocks have parent kinds like Block, not
    // File/Module/Class. Earlier heuristics misfired here. Now: a NAMED
    // method inside a Block must NOT be treated as a lambda, regardless
    // of its size.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let block = fx.batch.push_node(NodeBuilder::new(NodeKind::Block));
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, block, file)
        .unwrap();
    let method = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Method)
            .with_prop("name", Value::String("open".into()))
            .with_prop("range", Value::Range(range(1, 1, 0, 1))),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, method, block)
        .unwrap();
    for _ in 0..15 {
        push_child(&mut fx.batch, method, NodeKind::Call, range(1, 1, 0, 1));
    }
    assert!(LambdaComplexityRule.run(&fx.ctx()).is_empty());
}

// ---------- public_surface_size -------------------------------------------

#[test]
fn public_surface_size_flags_wide_class() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("Wide".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    for i in 0..21 {
        let m = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Method)
                .with_prop("name", Value::String(format!("method_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, m, class).unwrap();
    }
    let findings = PublicSurfaceSizeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.public_surface_size");
}

#[test]
fn public_surface_size_silent_when_methods_are_private() {
    // 25 methods, all underscore-prefixed = private. No fire.
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("Private".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    for i in 0..25 {
        let m = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Method)
                .with_prop("name", Value::String(format!("_internal_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, m, class).unwrap();
    }
    assert!(PublicSurfaceSizeRule.run(&fx.ctx()).is_empty());
}

// ---------- god_struct ----------------------------------------------------

#[test]
fn god_struct_flags_wide_and_tall_class() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("God".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    for i in 0..13 {
        let v = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Variable)
                .with_prop("name", Value::String(format!("field_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, v, class).unwrap();
    }
    for i in 0..16 {
        let m = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Method).with_prop("name", Value::String(format!("m_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, m, class).unwrap();
    }
    let findings = GodStructRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.god_struct");
}

#[test]
fn god_struct_silent_on_data_class_with_many_fields_few_methods() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "src/prod.rs");
    let class = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class).with_prop("name", Value::String("Record".into())),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, class, file)
        .unwrap();
    for i in 0..30 {
        let v = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Variable)
                .with_prop("name", Value::String(format!("field_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, v, class).unwrap();
    }
    for i in 0..3 {
        let m = fx.batch.push_node(
            NodeBuilder::new(NodeKind::Method).with_prop("name", Value::String(format!("m_{i}"))),
        );
        fx.batch.push_edge(EdgeKind::AST_PARENT, m, class).unwrap();
    }
    assert!(GodStructRule.run(&fx.ctx()).is_empty());
}

// ---------- expression_depth ---------------------------------------------

#[test]
fn expression_depth_flags_deeply_nested_brackets() {
    let body = b"let x = a(b(c(d(e(f(g(1)))))));\n".to_vec();
    let total = body.len() as u32;
    let mut fx = Fixture::new().with_source("src/prod.rs", body);
    let file = push_file(&mut fx.batch, "src/prod.rs");
    push_function(&mut fx.batch, file, "deep", range(1, 1, 0, total));
    let findings = ExpressionDepthRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.shape.expression_depth");
}

#[test]
fn expression_depth_silent_on_shallow_call() {
    let body = b"let x = a(b(c(1)));\n".to_vec();
    let total = body.len() as u32;
    let mut fx = Fixture::new().with_source("src/prod.rs", body);
    let file = push_file(&mut fx.batch, "src/prod.rs");
    push_function(&mut fx.batch, file, "shallow", range(1, 1, 0, total));
    assert!(ExpressionDepthRule.run(&fx.ctx()).is_empty());
}

// ---------- swallowed_with_log -------------------------------------------

#[test]
fn swallowed_with_log_flags_log_only_handler() {
    let body = b"try {\n    do_thing();\n} catch (e) {\n    console.error(e);\n}\n".to_vec();
    let mut fx = Fixture::new().with_source("src/prod.ts", body);
    let file = push_file(&mut fx.batch, "src/prod.ts");
    let handler_range = range(3, 5, 25, 60);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block).with_prop("range", Value::Range(handler_range)),
    );
    let try_range = range(1, 5, 0, 60);
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(try_range))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    let findings = SwallowedWithLogRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].rule_id,
        "cc.shape.swallowed_with_log_no_recovery"
    );
}

#[test]
fn swallowed_with_log_silent_when_handler_re_raises() {
    let body =
        b"try {\n    do_thing();\n} catch (e) {\n    console.error(e); throw e;\n}\n".to_vec();
    let mut fx = Fixture::new().with_source("src/prod.ts", body);
    let file = push_file(&mut fx.batch, "src/prod.ts");
    let handler_range = range(3, 5, 25, 70);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block).with_prop("range", Value::Range(handler_range)),
    );
    let try_range = range(1, 5, 0, 70);
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(try_range))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(SwallowedWithLogRule.run(&fx.ctx()).is_empty());
}

#[test]
fn swallowed_with_log_silent_when_no_log_call() {
    // Handler that swallows silently (no log, no propagate) is a different
    // rule's territory (R-ERR-BARE handles bare catches). Verify our rule
    // does NOT misclassify silent-swallow as log-and-swallow.
    let body = b"try {\n    do_thing();\n} catch (e) {\n    /* swallow */\n}\n".to_vec();
    let mut fx = Fixture::new().with_source("src/prod.ts", body);
    let file = push_file(&mut fx.batch, "src/prod.ts");
    let handler_range = range(3, 5, 25, 60);
    let handler = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Block).with_prop("range", Value::Range(handler_range)),
    );
    let try_range = range(1, 5, 0, 60);
    let try_node = fx.batch.push_node(
        NodeBuilder::new(NodeKind::Try)
            .with_prop("range", Value::Range(try_range))
            .with_prop("catches", Value::NodeList(vec![handler])),
    );
    fx.batch
        .push_edge(EdgeKind::AST_PARENT, try_node, file)
        .unwrap();
    assert!(SwallowedWithLogRule.run(&fx.ctx()).is_empty());
}
