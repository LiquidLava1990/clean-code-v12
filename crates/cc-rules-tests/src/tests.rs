//! Per-rule unit tests + a pack-registration integration test.
//!
//! Real probes (`assertion_free`, `tests_the_mock`) get a positive
//! case + a negative case + a non-test-file skip case.
//! Stubs get a registration-only assertion. The pack-level test
//! confirms all seven rules register and resolve.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::assertion_free::AssertionFreeRule;
use crate::coverage_hole_on_diff::CoverageHoleOnDiffRule;
use crate::flaky::FlakyRule;
use crate::mock_drift::MockDriftRule;
use crate::mutation_survivor_density::MutationSurvivorDensityRule;
use crate::tests_the_mock::TestsTheMockRule;
use crate::truth_score::TruthScoreRule;
use crate::BuiltinTestsPack;

// ---------- shared fixtures ----------------------------------------------

const TEST_PATH: &str = "tests/sample_test.py";
const NON_TEST_PATH: &str = "src/sample.py";

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

fn push_call_with_target(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee_ref: &str,
    target: &str,
    rng: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("target", Value::String(target.to_owned()))
            .with_prop("range", Value::Range(rng)),
    );
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

    #[allow(dead_code)]
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

// ---------- assertion_free ----------------------------------------------

#[test]
fn assertion_free_flags_test_with_no_assertions() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(
        &mut fx.batch,
        file,
        "test_login_returns_user",
        range(1, 5, 0, 80),
    );
    push_call(
        &mut fx.batch,
        fn_id,
        "login(\"alice\")",
        range(2, 2, 10, 30),
    );
    let findings = AssertionFreeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.assertion_free");
}

#[test]
fn assertion_free_silent_when_assert_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(
        &mut fx.batch,
        file,
        "test_login_returns_user",
        range(1, 5, 0, 80),
    );
    push_call(
        &mut fx.batch,
        fn_id,
        "login(\"alice\")",
        range(2, 2, 10, 30),
    );
    push_call(&mut fx.batch, fn_id, "assertEqual", range(3, 3, 31, 60));
    assert!(AssertionFreeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn assertion_free_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_helper", range(1, 5, 0, 80));
    push_call(&mut fx.batch, fn_id, "do_thing()", range(2, 2, 10, 30));
    assert!(AssertionFreeRule.run(&fx.ctx()).is_empty());
}

// ---------- tests_the_mock ----------------------------------------------

#[test]
fn tests_the_mock_flags_mock_only_assertions() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(
        &mut fx.batch,
        file,
        "test_login_calls_db",
        range(1, 5, 0, 80),
    );
    push_call_with_target(
        &mut fx.batch,
        fn_id,
        "assertEqual",
        "mock_db.calls",
        range(2, 2, 10, 40),
    );
    push_call_with_target(
        &mut fx.batch,
        fn_id,
        "assertTrue",
        "fake_user.was_called",
        range(3, 3, 41, 70),
    );
    let findings = TestsTheMockRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.tests_the_mock");
}

#[test]
fn tests_the_mock_silent_when_real_assertion_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(
        &mut fx.batch,
        file,
        "test_login_returns_user",
        range(1, 5, 0, 80),
    );
    push_call_with_target(
        &mut fx.batch,
        fn_id,
        "assertEqual",
        "mock_db.calls",
        range(2, 2, 10, 40),
    );
    push_call_with_target(
        &mut fx.batch,
        fn_id,
        "assertEqual",
        "user.name",
        range(3, 3, 41, 70),
    );
    assert!(TestsTheMockRule.run(&fx.ctx()).is_empty());
}

#[test]
fn tests_the_mock_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_helper", range(1, 5, 0, 80));
    push_call_with_target(
        &mut fx.batch,
        fn_id,
        "assertEqual",
        "mock_db.calls",
        range(2, 2, 10, 40),
    );
    assert!(TestsTheMockRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs (registration-only) ------------------------------------

#[test]
fn mock_drift_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(MockDriftRule.run(&fx.ctx()).is_empty());
}

#[test]
fn flaky_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(FlakyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn coverage_hole_on_diff_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(CoverageHoleOnDiffRule.run(&fx.ctx()).is_empty());
}

#[test]
fn mutation_survivor_density_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(MutationSurvivorDensityRule.run(&fx.ctx()).is_empty());
}

#[test]
fn truth_score_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(TruthScoreRule.run(&fx.ctx()).is_empty());
}

// ---------- parallel_test_uses_shared_t (Phase 8) ------------------------

use crate::assertion_free_jest::AssertionFreeJestRule;
use crate::parallel_test_uses_shared_t::ParallelTestUsesSharedTRule;
use crate::testify_assertion_misuse::TestifyAssertionMisuseRule;

#[test]
fn parallel_test_shared_t_flags_outer_t_in_subtest_body() {
    let body = "func TestThing(t *testing.T) {\n    \
                    t.Run(\"a\", func(subT *testing.T) {\n        \
                        subT.Parallel()\n        \
                        if got := work(); got != 1 { t.Fatalf(\"oops\") }\n    \
                    })\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/svc_test.go");
    let findings = ParallelTestUsesSharedTRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.parallel_test_uses_shared_t");
}

#[test]
fn parallel_test_shared_t_silent_when_param_named_t() {
    let body = "func TestThing(t *testing.T) {\n    \
                    t.Run(\"a\", func(t *testing.T) {\n        \
                        t.Parallel()\n        \
                        if got := work(); got != 1 { t.Fatalf(\"oops\") }\n    \
                    })\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/svc_test.go");
    assert!(ParallelTestUsesSharedTRule.run(&fx.ctx()).is_empty());
}

#[test]
fn parallel_test_shared_t_silent_when_subtest_only_uses_inner_param() {
    let body = "func TestThing(t *testing.T) {\n    \
                    t.Run(\"a\", func(subT *testing.T) {\n        \
                        subT.Parallel()\n        \
                        if got := work(); got != 1 { subT.Fatalf(\"oops\") }\n    \
                    })\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/svc_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/svc_test.go");
    assert!(ParallelTestUsesSharedTRule.run(&fx.ctx()).is_empty());
}

// ---------- testify_assertion_misuse (Phase 8) ---------------------------

#[test]
fn testify_misuse_flags_got_then_literal() {
    let body = "func TestX(t *testing.T) {\n    \
                    assert.Equal(t, got, 42)\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/x_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/x_test.go");
    let findings = TestifyAssertionMisuseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.testify_assertion_misuse");
}

#[test]
fn testify_misuse_silent_when_literal_is_first() {
    let body = "func TestX(t *testing.T) {\n    \
                    assert.Equal(t, 42, got)\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/x_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/x_test.go");
    assert!(TestifyAssertionMisuseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn testify_misuse_silent_when_both_args_variables() {
    let body = "func TestX(t *testing.T) {\n    \
                    assert.Equal(t, want, got)\n\
                }\n";
    let mut fx = Fixture::new().with_source("internal/x_test.go", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "internal/x_test.go");
    assert!(TestifyAssertionMisuseRule.run(&fx.ctx()).is_empty());
}

// ---------- assertion_free_jest (Phase 8) --------------------------------

#[test]
fn assertion_free_jest_flags_test_with_no_expect() {
    let body = "test('login works', () => {\n    \
                    const u = login('alice');\n    \
                    console.log(u);\n\
                });\n";
    let mut fx =
        Fixture::new().with_source("src/__tests__/login.test.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/__tests__/login.test.ts");
    let findings = AssertionFreeJestRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.assertion_free_jest");
}

#[test]
fn assertion_free_jest_silent_when_expect_present() {
    let body = "test('login works', () => {\n    \
                    const u = login('alice');\n    \
                    expect(u.name).toBe('alice');\n\
                });\n";
    let mut fx =
        Fixture::new().with_source("src/__tests__/login.test.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/__tests__/login.test.ts");
    assert!(AssertionFreeJestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn assertion_free_jest_silent_outside_test_files() {
    let body = "test('would-fire', () => {\n    \
                    work();\n\
                });\n";
    let mut fx = Fixture::new().with_source("src/lib.ts", body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, "src/lib.ts");
    assert!(AssertionFreeJestRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_ten_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTestsPack)
        .expect("Family-8 pack registers without error");
    assert_eq!(reg.rules().count(), 10);
    for slug in [
        "cc.test.assertion_free",
        "cc.test.mock_drift",
        "cc.test.flaky",
        "cc.test.coverage_hole_on_diff",
        "cc.test.tests_the_mock",
        "cc.test.mutation_survivor_density",
        "cc.test.truth_score",
        "cc.test.parallel_test_uses_shared_t",
        "cc.test.testify_assertion_misuse",
        "cc.test.assertion_free_jest",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
