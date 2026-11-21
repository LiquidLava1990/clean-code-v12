//! Phase 12 (final OSS long-tail sweep) per-rule unit tests.
//!
//! Lives in its own module to keep `tests.rs` under the 1500-LOC
//! Tier-0 ceiling. Each rule has at least one positive (violating)
//! and one negative (clean) case, plus an edge case where useful.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext};

use crate::govet_nilness_check::GovetNilnessCheckRule;
use crate::govet_printf_format::GovetPrintfFormatRule;
use crate::govet_struct_tag_well_formed::GovetStructTagWellFormedRule;
use crate::python_assert_in_production::PythonAssertInProductionRule;

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

fn push_file(batch: &mut CpgWriteBatch, path: &str, language: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String(language.to_owned())),
    )
}

// ---------- govet_nilness_check ----------------------------------------

#[test]
fn govet_nilness_flags_use_after_nil_assign() {
    let body = "package main\n\
                func f(x *T) {\n    \
                    if x != nil {\n        \
                        log(x)\n    \
                    }\n    \
                    x = nil\n    \
                    use(x.Field)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    let findings = GovetNilnessCheckRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_nilness_check");
}

#[test]
fn govet_nilness_silent_when_no_nil_assign() {
    let body = "package main\n\
                func f(x *T) {\n    \
                    if x != nil {\n        \
                        log(x)\n    \
                    }\n    \
                    use(x.Field)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    assert!(GovetNilnessCheckRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_nilness_silent_in_test_files() {
    let body = "package main\n\
                func f(x *T) {\n    \
                    if x != nil {\n        \
                        log(x)\n    \
                    }\n    \
                    x = nil\n    \
                    use(x.Field)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc_test.go", "go");
    assert!(GovetNilnessCheckRule.run(&fx.ctx()).is_empty());
}

// ---------- govet_printf_format ----------------------------------------

#[test]
fn govet_printf_flags_too_few_args() {
    let body = "package main\n\
                func f(x string) {\n    \
                    fmt.Printf(\"%s %d\", x)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    let findings = GovetPrintfFormatRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_printf_format");
}

#[test]
fn govet_printf_flags_go_specific_verbs() {
    let body = "package main\n\
                func f(p any) {\n    \
                    fmt.Errorf(\"got %T (%+v)\", p)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    let findings = GovetPrintfFormatRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
}

#[test]
fn govet_printf_silent_on_balanced_call() {
    let body = "package main\n\
                func f(s string, n int) {\n    \
                    fmt.Printf(\"%s %d\", s, n)\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    assert!(GovetPrintfFormatRule.run(&fx.ctx()).is_empty());
}

// ---------- govet_struct_tag_well_formed -------------------------------

#[test]
fn govet_struct_tag_flags_missing_quotes() {
    let body = "package main\n\
                type User struct {\n    \
                    Age int `json:age`\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    let findings = GovetStructTagWellFormedRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_struct_tag_well_formed");
}

#[test]
fn govet_struct_tag_flags_missing_colon() {
    let body = "package main\n\
                type User struct {\n    \
                    Tag string `jsonname`\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    assert!(!GovetStructTagWellFormedRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_struct_tag_silent_on_well_formed_pairs() {
    let body = "package main\n\
                type User struct {\n    \
                    Name string `json:\"name\" yaml:\"name\"`\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go", "go");
    assert!(GovetStructTagWellFormedRule.run(&fx.ctx()).is_empty());
}

// ---------- python_assert_in_production --------------------------------

#[test]
fn python_assert_flags_production_assert() {
    let body = "def authorize(user):\n    \
                    assert user.is_admin\n    \
                    do_thing()\n";
    let mut fx = Fixture::new().with_source("src/auth.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/auth.py", "python");
    let findings = PythonAssertInProductionRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.python_assert_in_production");
}

#[test]
fn python_assert_silent_in_test_files() {
    let body = "def test_thing():\n    \
                    assert 1 == 1\n";
    let mut fx = Fixture::new().with_source("tests/test_auth.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "tests/test_auth.py", "python");
    assert!(PythonAssertInProductionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn python_assert_silent_in_conftest() {
    let body = "import pytest\n\
                def fixture():\n    \
                    assert True\n";
    let mut fx = Fixture::new().with_source("conftest.py", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "conftest.py", "python");
    assert!(PythonAssertInProductionRule.run(&fx.ctx()).is_empty());
}
