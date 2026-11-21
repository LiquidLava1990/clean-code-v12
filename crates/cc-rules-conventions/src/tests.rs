//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive (layout-shaped fixture) and
//! one negative (path outside the layout or clean layout path) case. The
//! pack-level test confirms five rules registered.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::config_json_for_non_auth::ConfigJsonForNonAuthRule;
use crate::file_claim_bypass::FileClaimBypassRule;
use crate::module_missing_manifest::ModuleMissingManifestRule;
use crate::startup_py_exists::StartupPyExistsRule;
use crate::untyped_event::UntypedEventRule;
use crate::BuiltinConventionsPack;

// ---------- shared fixtures ------------------------------------------------

const LAYOUT_PATH: &str = "platform/modules/foo/foo.py";
const NON_LAYOUT_PATH: &str = "src/sample.py";

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
            .with_prop("language", Value::String("python".into())),
    )
}

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range(1, 10, 0, 80))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee: &str,
    arg: Option<&str>,
    rng: Range,
) -> NodeId {
    let mut builder = NodeBuilder::new(NodeKind::Call)
        .with_prop("callee_ref", Value::String(callee.to_owned()))
        .with_prop("range", Value::Range(rng));
    if let Some(a) = arg {
        builder = builder.with_prop("first_arg_value", Value::String(a.to_owned()));
    }
    let id = batch.push_node(builder);
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
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

// ---------- config_json_for_non_auth --------------------------------------

#[test]
fn config_json_flags_non_auth_top_level_key() {
    let mut fx = Fixture::new();
    let path = "platform/config.json";
    push_file(&mut fx.batch, path);
    fx.source.insert(
        path,
        br#"{"db_pool_size": 10, "oauth_google": {"access_token": "xxx"}}"#.to_vec(),
    );
    let findings = ConfigJsonForNonAuthRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.convention.config_json_for_non_auth"
    );
}

#[test]
fn config_json_silent_when_only_auth_keys() {
    let mut fx = Fixture::new();
    let path = "platform/config.json";
    push_file(&mut fx.batch, path);
    fx.source.insert(
        path,
        br#"{"oauth_google": {"access_token": "xxx", "refresh_token": "yyy"}}"#.to_vec(),
    );
    assert!(ConfigJsonForNonAuthRule.run(&fx.ctx()).is_empty());
}

#[test]
fn config_json_silent_outside_layout() {
    let mut fx = Fixture::new();
    let path = "src/config.json";
    push_file(&mut fx.batch, path);
    fx.source.insert(
        path,
        br#"{"db_pool_size": 10, "log_level": "info"}"#.to_vec(),
    );
    assert!(ConfigJsonForNonAuthRule.run(&fx.ctx()).is_empty());
}

// ---------- startup_py_exists ---------------------------------------------

#[test]
fn startup_py_exists_flags_layout_startup() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "platform/startup.py");
    let findings = StartupPyExistsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.convention.startup_py_exists");
}

#[test]
fn startup_py_exists_silent_outside_layout() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "other_project/startup.py");
    assert!(StartupPyExistsRule.run(&fx.ctx()).is_empty());
}

// ---------- module_missing_manifest ---------------------------------------

#[test]
fn module_missing_manifest_flags_module_without_manifest() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "platform/modules/foo/foo.py");
    fx.source
        .insert("platform/modules/foo/foo.py", b"# foo".to_vec());
    let findings = ModuleMissingManifestRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.convention.module_missing_manifest");
}

#[test]
fn module_missing_manifest_silent_when_manifest_present() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "platform/modules/bar/bar.py");
    push_file(&mut fx.batch, "platform/modules/bar/__manifest__.py");
    fx.source
        .insert("platform/modules/bar/bar.py", b"# bar".to_vec());
    fx.source.insert(
        "platform/modules/bar/__manifest__.py",
        b"# manifest".to_vec(),
    );
    assert!(ModuleMissingManifestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn module_missing_manifest_silent_outside_layout() {
    let mut fx = Fixture::new();
    push_file(&mut fx.batch, "src/mymod/foo.py");
    fx.source.insert("src/mymod/foo.py", b"# foo".to_vec());
    assert!(ModuleMissingManifestRule.run(&fx.ctx()).is_empty());
}

// ---------- untyped_event -------------------------------------------------

#[test]
fn untyped_event_flags_string_literal_emit() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, LAYOUT_PATH);
    push_call(
        &mut fx.batch,
        file,
        "bus.emit",
        Some("user.created"),
        range(2, 2, 0, 28),
    );
    let findings = UntypedEventRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.convention.untyped_event");
}

#[test]
fn untyped_event_silent_outside_layout() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_LAYOUT_PATH);
    push_call(
        &mut fx.batch,
        file,
        "bus.emit",
        Some("user.created"),
        range(2, 2, 0, 28),
    );
    assert!(UntypedEventRule.run(&fx.ctx()).is_empty());
}

#[test]
fn untyped_event_silent_when_no_literal_arg() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, LAYOUT_PATH);
    // No first_arg_value → identifier reference, treated as typed contract.
    push_call(&mut fx.batch, file, "bus.emit", None, range(2, 2, 0, 28));
    assert!(UntypedEventRule.run(&fx.ctx()).is_empty());
}

// ---------- file_claim_bypass --------------------------------------------

#[test]
fn file_claim_bypass_flags_data_write_in_layout() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, LAYOUT_PATH);
    let fun = push_function(&mut fx.batch, file, "save");
    push_call(
        &mut fx.batch,
        fun,
        "open",
        Some("data/state.yaml"),
        range(2, 2, 0, 28),
    );
    let findings = FileClaimBypassRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.convention.file_claim_bypass");
}

#[test]
fn file_claim_bypass_silent_with_claim_scope() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, LAYOUT_PATH);
    let fun = push_function(&mut fx.batch, file, "save");
    push_call(
        &mut fx.batch,
        fun,
        "FileClaimRegistry.sync_claim_scope",
        None,
        range(2, 2, 100, 138),
    );
    push_call(
        &mut fx.batch,
        fun,
        "open",
        Some("data/state.yaml"),
        range(3, 3, 200, 228),
    );
    assert!(FileClaimBypassRule.run(&fx.ctx()).is_empty());
}

#[test]
fn file_claim_bypass_silent_outside_layout() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_LAYOUT_PATH);
    let fun = push_function(&mut fx.batch, file, "save");
    push_call(
        &mut fx.batch,
        fun,
        "open",
        Some("data/state.yaml"),
        range(2, 2, 0, 28),
    );
    assert!(FileClaimBypassRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_five_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinConventionsPack)
        .expect("Family-24 pack registers without error");
    assert_eq!(reg.rules().count(), 5);
    for slug in [
        "cc.convention.config_json_for_non_auth",
        "cc.convention.startup_py_exists",
        "cc.convention.module_missing_manifest",
        "cc.convention.untyped_event",
        "cc.convention.file_claim_bypass",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}

#[allow(dead_code)]
fn _phantom_path(p: &str) -> Utf8PathBuf {
    Utf8PathBuf::from(p)
}
