//! Per-rule unit tests + a pack-registration integration test.
//!
//! The three stub probes only carry registration tests (their `run`
//! method is unconditionally empty). The real probe
//! `response_shape_drift` carries one positive (drifting) and one
//! negative (consistent) case.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::breaking_change_no_version::BreakingChangeNoVersionRule;
use crate::client_server_drift::ClientServerDriftRule;
use crate::response_shape_drift::ResponseShapeDriftRule;
use crate::schema_vs_db_drift::SchemaVsDbDriftRule;
use crate::BuiltinApiPack;

// ---------- shared fixtures ---------------------------------------------

const SAMPLE_PATH: &str = "src/handlers.py";

const fn pos(line: u32, offset: u32) -> Position {
    Position::new(line, 1, offset)
}

const fn range(start_line: u32, end_line: u32, start_off: u32, end_off: u32) -> Range {
    Range::new(pos(start_line, start_off), pos(end_line, end_off))
}

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("python".into())),
    )
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

fn push_handler_fn(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    return_type: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("return_type", Value::String(return_type.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_return(batch: &mut CpgWriteBatch, parent: NodeId, rng: Range) -> NodeId {
    let id =
        batch.push_node(NodeBuilder::new(NodeKind::Return).with_prop("range", Value::Range(rng)));
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

// ---------- response_shape_drift ----------------------------------------

#[test]
fn response_shape_drift_flags_diverging_field_sets() {
    let body = "def get_user_handler():\n    if x:\n        return {\"id\": 1, \"name\": \"a\"}\n    return {\"id\": 1, \"email\": \"a@b\"}\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let total_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let func = push_handler_fn(
        &mut fx.batch,
        file,
        "get_user_handler",
        "JsonResponse",
        range(1, 4, 0, total_len),
    );
    // First return: {"id": 1, "name": "a"}
    let ret1_start = u32::try_from(body.find("return {\"id\": 1, \"name\"").unwrap_or(0))
        .unwrap_or(0)
        .saturating_add(7);
    let ret1_end = ret1_start.saturating_add(20);
    push_return(&mut fx.batch, func, range(3, 3, ret1_start, ret1_end));
    // Second return: {"id": 1, "email": "a@b"}
    let ret2_start = u32::try_from(body.rfind("return {\"id\": 1, \"email\"").unwrap_or(0))
        .unwrap_or(0)
        .saturating_add(7);
    let ret2_end = ret2_start.saturating_add(22);
    push_return(&mut fx.batch, func, range(4, 4, ret2_start, ret2_end));
    let findings = ResponseShapeDriftRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.api.response_shape_drift");
}

#[test]
fn response_shape_drift_silent_on_consistent_returns() {
    let body = "def list_users_handler():\n    if x:\n        return {\"id\": 1, \"name\": \"a\"}\n    return {\"id\": 2, \"name\": \"b\"}\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let total_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let func = push_handler_fn(
        &mut fx.batch,
        file,
        "list_users_handler",
        "JsonResponse",
        range(1, 4, 0, total_len),
    );
    let ret1_start = u32::try_from(body.find("return {\"id\": 1").unwrap_or(0))
        .unwrap_or(0)
        .saturating_add(7);
    let ret1_end = ret1_start.saturating_add(22);
    push_return(&mut fx.batch, func, range(3, 3, ret1_start, ret1_end));
    let ret2_start = u32::try_from(body.rfind("return {\"id\": 2").unwrap_or(0))
        .unwrap_or(0)
        .saturating_add(7);
    let ret2_end = ret2_start.saturating_add(22);
    push_return(&mut fx.batch, func, range(4, 4, ret2_start, ret2_end));
    assert!(ResponseShapeDriftRule.run(&fx.ctx()).is_empty());
}

#[test]
fn response_shape_drift_silent_on_non_handler_function() {
    // Same diverging shapes, but the function is not handler-shaped —
    // no flag.
    let body =
        "def helper():\n    if x:\n        return {\"id\": 1}\n    return {\"email\": \"a\"}\n";
    let mut fx = Fixture::new().with_source(SAMPLE_PATH, body.as_bytes().to_vec());
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let total_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let func = push_handler_fn(
        &mut fx.batch,
        file,
        "helper",
        "dict",
        range(1, 4, 0, total_len),
    );
    push_return(&mut fx.batch, func, range(3, 3, 20, 35));
    push_return(&mut fx.batch, func, range(4, 4, 45, 60));
    assert!(ResponseShapeDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- stub registration tests -------------------------------------

#[test]
fn client_server_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(ClientServerDriftRule.run(&fx.ctx()).is_empty());
}

#[test]
fn breaking_change_no_version_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(BreakingChangeNoVersionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn schema_vs_db_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(SchemaVsDbDriftRule.run(&fx.ctx()).is_empty());
}

// ---------- struct_tag_required (Phase 8) -------------------------------

use crate::errcode_collision::ErrCodeCollisionRule;
use crate::struct_tag_required::StructTagRequiredRule;

#[test]
fn struct_tag_required_flags_missing_tag_when_peers_have_one() {
    let body = "package m\n\
                type User struct {\n    \
                    ID    int    `json:\"id\"`\n    \
                    Name  string `json:\"name\"`\n    \
                    Email string\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/m.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/m.go");
    let findings = StructTagRequiredRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.api.struct_tag_required");
}

#[test]
fn struct_tag_required_silent_when_no_field_has_tag() {
    let body = "package m\n\
                type Internal struct {\n    \
                    ID    int\n    \
                    Name  string\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/m.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/m.go");
    assert!(StructTagRequiredRule.run(&fx.ctx()).is_empty());
}

#[test]
fn struct_tag_required_silent_when_unexported_field_lacks_tag() {
    let body = "package m\n\
                type User struct {\n    \
                    ID   int    `json:\"id\"`\n    \
                    Name string `json:\"name\"`\n    \
                    cache string\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/m.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/m.go");
    assert!(StructTagRequiredRule.run(&fx.ctx()).is_empty());
}

// ---------- errcode_collision (Phase 8) ---------------------------------

#[test]
fn errcode_collision_flags_same_code_in_two_functions() {
    let body = "fn handle_a() -> Result<()> {\n    \
                    Err(ErrCode::new(\"TOKEN_EXPIRED\"))\n\
                }\n\
                fn handle_b() -> Result<()> {\n    \
                    Err(ErrCode::new(\"TOKEN_EXPIRED\"))\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/auth.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/auth.rs");
    let findings = ErrCodeCollisionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.api.errcode_collision");
}

#[test]
fn errcode_collision_silent_when_codes_distinct() {
    let body = "fn handle_a() -> Result<()> {\n    \
                    Err(ErrCode::new(\"TOKEN_EXPIRED\"))\n\
                }\n\
                fn handle_b() -> Result<()> {\n    \
                    Err(ErrCode::new(\"TOKEN_MALFORMED\"))\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/auth.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/auth.rs");
    assert!(ErrCodeCollisionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn errcode_collision_silent_when_same_function_uses_code_twice() {
    let body = "fn handle() -> Result<()> {\n    \
                    if x { return Err(ErrCode::new(\"DUP\")) }\n    \
                    Err(ErrCode::new(\"DUP\"))\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/auth.rs", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/auth.rs");
    assert!(ErrCodeCollisionRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_six_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinApiPack)
        .expect("Family-9 pack registers without error");
    assert_eq!(reg.rules().count(), 6);
    for slug in [
        "cc.api.client_server_drift",
        "cc.api.breaking_change_no_version",
        "cc.api.schema_vs_db_drift",
        "cc.api.response_shape_drift",
        "cc.api.struct_tag_required",
        "cc.api.errcode_collision",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
