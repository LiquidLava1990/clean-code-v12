//! Phase 11 (Go govet long-tail) per-rule unit tests.
//!
//! Lives in its own module file to keep `tests.rs` under the 1500-LOC
//! Tier-0 ceiling (`cc.shape.file_length`). Each rule has at least one
//! positive (violating) and one negative (clean) case.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, NodeBuilder, NodeId, NodeKind, Value};
use cc_rules::{InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext};

use crate::govet_assign_to_self::GovetAssignToSelfRule;
use crate::govet_copylocks::GovetCopylocksRule;
use crate::govet_lostcancel::GovetLostcancelRule;
use crate::govet_unkeyed_composite::GovetUnkeyedCompositeRule;
use crate::govet_unreachable_code::GovetUnreachableCodeRule;

/// Local fixture mirror — kept independent of the Phase 3-10
/// `tests::Fixture` to avoid cross-module visibility weirdness.
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

fn push_file(batch: &mut CpgWriteBatch, path: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String("go".into())),
    )
}

// ---------- govet_unreachable_code --------------------------------------

#[test]
fn govet_unreachable_flags_after_return() {
    let body = "package main\n\
                func f() int {\n    \
                    return 1\n    \
                    x := 2\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = GovetUnreachableCodeRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_unreachable_code");
}

#[test]
fn govet_unreachable_silent_when_close_brace_follows() {
    let body = "package main\n\
                func f() int {\n    \
                    return 1\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetUnreachableCodeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_unreachable_silent_in_test_files() {
    let body = "package main\n\
                func f() int {\n    \
                    return 1\n    \
                    x := 2\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc_test.go");
    assert!(GovetUnreachableCodeRule.run(&fx.ctx()).is_empty());
}

// ---------- govet_lostcancel --------------------------------------------

#[test]
fn govet_lostcancel_flags_discarded_cancel() {
    let body = "package main\n\
                import \"context\"\n\
                func f() {\n    \
                    ctx, _ := context.WithCancel(context.Background())\n    \
                    _ = ctx\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = GovetLostcancelRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_lostcancel");
}

#[test]
fn govet_lostcancel_silent_when_cancel_bound() {
    let body = "package main\n\
                import \"context\"\n\
                func f() {\n    \
                    ctx, cancel := context.WithCancel(context.Background())\n    \
                    defer cancel()\n    \
                    _ = ctx\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetLostcancelRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_lostcancel_flags_with_timeout() {
    let body = "package main\n\
                import \"context\"\n\
                import \"time\"\n\
                func f() {\n    \
                    ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)\n    \
                    _ = ctx\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert_eq!(GovetLostcancelRule.run(&fx.ctx()).len(), 1);
}

// ---------- govet_assign_to_self ----------------------------------------

#[test]
fn govet_assign_to_self_flags_x_eq_x() {
    let body = "package main\n\
                func f(x int) {\n    \
                    x = x\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = GovetAssignToSelfRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_assign_to_self");
}

#[test]
fn govet_assign_to_self_silent_for_genuine_assign() {
    let body = "package main\n\
                func f(x, y int) {\n    \
                    x = y\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetAssignToSelfRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_assign_to_self_flags_field_self_assign() {
    let body = "package main\n\
                func f(s *S) {\n    \
                    s.field = s.field\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert_eq!(GovetAssignToSelfRule.run(&fx.ctx()).len(), 1);
}

// ---------- govet_copylocks ---------------------------------------------

#[test]
fn govet_copylocks_flags_mutex_copy() {
    let body = "package main\n\
                import \"sync\"\n\
                func f() {\n    \
                    var m sync.Mutex\n    \
                    n := m\n    \
                    _ = n\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = GovetCopylocksRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_copylocks");
}

#[test]
fn govet_copylocks_silent_for_pointer_pass() {
    let body = "package main\n\
                import \"sync\"\n\
                func f() {\n    \
                    var m sync.Mutex\n    \
                    n := &m\n    \
                    _ = n\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetCopylocksRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_copylocks_silent_when_no_lock_binding() {
    let body = "package main\n\
                func f(x int) {\n    \
                    n := x\n    \
                    _ = n\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetCopylocksRule.run(&fx.ctx()).is_empty());
}

// ---------- govet_unkeyed_composite -------------------------------------

#[test]
fn govet_unkeyed_composite_flags_positional_literal() {
    let body = "package main\n\
                type Foo struct{ A int; B string; C bool }\n\
                func f() Foo {\n    \
                    return Foo{1, \"bar\", true}\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    let findings = GovetUnkeyedCompositeRule.run(&fx.ctx());
    assert!(!findings.is_empty(), "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.bug.govet_unkeyed_composite");
}

#[test]
fn govet_unkeyed_composite_silent_for_keyed_literal() {
    let body = "package main\n\
                type Foo struct{ A int; B string; C bool }\n\
                func f() Foo {\n    \
                    return Foo{A: 1, B: \"bar\", C: true}\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    assert!(GovetUnkeyedCompositeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn govet_unkeyed_composite_silent_for_single_value() {
    let body = "package main\n\
                type Wrapper struct{ V int }\n\
                func f() Wrapper {\n    \
                    return Wrapper{42}\n\
                }\n";
    let mut fx = Fixture::new().with_source("src/svc.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/svc.go");
    // Single-value positional literal is conservative — skip.
    assert!(GovetUnkeyedCompositeRule.run(&fx.ctx()).is_empty());
}
