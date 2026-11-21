//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each real rule has at least one positive (violating) and one
//! negative (clean) case. The stub rule has a registration test only
//! (no findings to assert). The pack-level test confirms all four
//! rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::audit_log_gap::AuditLogGapRule;
use crate::gdpr_pattern::GdprPatternRule;
use crate::license_violation::LicenseViolationRule;
use crate::pii_handling::PiiHandlingRule;
use crate::BuiltinCompliancePack;

// ---------- shared fixtures ----------------------------------------------

const SAMPLE_PATH: &str = "src/sample.py";

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

fn push_variable(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    type_text: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Variable)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("type", Value::String(type_text.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee_ref: &str, rng: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

// ---------- pii_handling ------------------------------------------------

#[test]
fn pii_handling_flags_unencrypted_email_field() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_variable(&mut fx.batch, file, "email", "str", range(1, 1, 0, 12));
    let findings = PiiHandlingRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.compliance.pii_handling");
}

#[test]
fn pii_handling_silent_when_field_marked_encrypted() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_variable(
        &mut fx.batch,
        file,
        "email",
        "EncryptedField[str]",
        range(1, 1, 0, 30),
    );
    assert!(PiiHandlingRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pii_handling_silent_in_test_files() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, "tests/test_user_fixtures.py");
    push_variable(&mut fx.batch, file, "email", "str", range(1, 1, 0, 12));
    assert!(PiiHandlingRule.run(&fx.ctx()).is_empty());
}

// ---------- gdpr_pattern (STUB) ----------------------------------------

#[test]
fn gdpr_pattern_stub_emits_nothing() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::Class)
            .with_prop("name", Value::String("User".into()))
            .with_prop("range", Value::Range(range(1, 5, 0, 50))),
    );
    let _ = file;
    // Phase-5 stub: zero findings regardless of input.
    assert!(GdprPatternRule.run(&fx.ctx()).is_empty());
}

// ---------- audit_log_gap ----------------------------------------------

#[test]
fn audit_log_gap_flags_admin_function_without_audit_call() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "admin_delete_tenant",
        range(1, 5, 0, 50),
    );
    let findings = AuditLogGapRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.compliance.audit_log_gap");
}

#[test]
fn audit_log_gap_silent_when_audit_call_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(
        &mut fx.batch,
        file,
        "admin_delete_tenant",
        range(1, 5, 0, 50),
    );
    push_call(&mut fx.batch, file, "audit_log", range(3, 3, 20, 35));
    assert!(AuditLogGapRule.run(&fx.ctx()).is_empty());
}

#[test]
fn audit_log_gap_silent_for_non_privileged_function() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    push_function(&mut fx.batch, file, "compute_stats", range(1, 5, 0, 50));
    assert!(AuditLogGapRule.run(&fx.ctx()).is_empty());
}

// ---------- license_violation ------------------------------------------

#[test]
fn license_violation_flags_gpl_alongside_mit() {
    let gpl_text = "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007\n";
    let mit_text = "MIT License\n\nCopyright (c) 2026 …\n";
    let mut fx = Fixture::new()
        .with_source("LICENSE-GPL", gpl_text.as_bytes().to_vec())
        .with_source("LICENSE", mit_text.as_bytes().to_vec());
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("LICENSE-GPL".into()))
            .with_prop("language", Value::String("text".into())),
    );
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("LICENSE".into()))
            .with_prop("language", Value::String("text".into())),
    );
    let findings = LicenseViolationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.compliance.license_violation");
    assert!(findings[0].message.headline.contains("LICENSE-GPL"));
}

#[test]
fn license_violation_silent_when_only_mit_present() {
    let mit_text = "MIT License\n\nCopyright (c) 2026 …\n";
    let mut fx = Fixture::new().with_source("LICENSE", mit_text.as_bytes().to_vec());
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("LICENSE".into()))
            .with_prop("language", Value::String("text".into())),
    );
    assert!(LicenseViolationRule.run(&fx.ctx()).is_empty());
}

#[test]
fn license_violation_silent_when_only_gpl_present() {
    let gpl_text = "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007\n";
    let mut fx = Fixture::new().with_source("LICENSE", gpl_text.as_bytes().to_vec());
    fx.batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("LICENSE".into()))
            .with_prop("language", Value::String("text".into())),
    );
    assert!(LicenseViolationRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_four_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinCompliancePack)
        .expect("Family-21 pack registers without error");
    assert_eq!(reg.rules().count(), 4);
    for slug in [
        "cc.compliance.pii_handling",
        "cc.compliance.gdpr_pattern",
        "cc.compliance.audit_log_gap",
        "cc.compliance.license_violation",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
