//! Per-rule unit tests + a pack-registration integration test.

use camino::Utf8PathBuf;
use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::assertion_count_zero::AssertionCountZeroRule;
use crate::disabled_test::DisabledTestRule;
use crate::flaky_iteration::FlakyIterationRule;
use crate::gigantic_test_function::GiganticTestFunctionRule;
use crate::no_negative_case::NoNegativeCaseRule;
use crate::non_isolated_state::NonIsolatedStateRule;
use crate::private_helper_imported_into_test::PrivateHelperImportedIntoTestRule;
use crate::shared_setup_in_assertion::SharedSetupInAssertionRule;
use crate::test_imports_test_module::TestImportsTestModuleRule;
use crate::unconditional_assert_true::UnconditionalAssertTrueRule;
use crate::BuiltinTestDesignPack;

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

fn push_function(batch: &mut CpgWriteBatch, parent: NodeId, name: &str, range: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Function)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee_ref: &str, range: Range) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("range", Value::Range(range)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call_with_args(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee_ref: &str,
    arguments: &str,
    range: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee_ref.to_owned()))
            .with_prop("arguments", Value::String(arguments.to_owned()))
            .with_prop("range", Value::Range(range)),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_decorator(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    name: &str,
    expression: &str,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Decorator)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("expression", Value::String(expression.to_owned())),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_loop(batch: &mut CpgWriteBatch, parent: NodeId, range: Range) -> NodeId {
    let id =
        batch.push_node(NodeBuilder::new(NodeKind::Loop).with_prop("range", Value::Range(range)));
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_import(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    module_path: &str,
    range: Range,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Import)
            .with_prop("module_path", Value::String(module_path.to_owned()))
            .with_prop("range", Value::Range(range)),
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

#[allow(dead_code)]
fn _silence_camino() {
    let _ = Utf8PathBuf::from(TEST_PATH);
}

// ---------- unconditional_assert_true -----------------------------------

#[test]
fn unconditional_assert_true_flags_assert_true() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_thing", range(1, 5, 0, 80));
    push_call_with_args(
        &mut fx.batch,
        fn_id,
        "assertTrue",
        "True",
        range(2, 2, 10, 30),
    );
    let findings = UnconditionalAssertTrueRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.unconditional_assert_true");
}

#[test]
fn unconditional_assert_true_silent_for_real_assertion() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_thing", range(1, 5, 0, 80));
    push_call_with_args(
        &mut fx.batch,
        fn_id,
        "assertEqual",
        "user.name, 'alice'",
        range(2, 2, 10, 30),
    );
    assert!(UnconditionalAssertTrueRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unconditional_assert_true_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "helper", range(1, 5, 0, 80));
    push_call_with_args(
        &mut fx.batch,
        fn_id,
        "assertTrue",
        "True",
        range(2, 2, 10, 30),
    );
    assert!(UnconditionalAssertTrueRule.run(&fx.ctx()).is_empty());
}

// ---------- disabled_test -----------------------------------------------

#[test]
fn disabled_test_flags_marker_without_reason() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_thing", range(2, 6, 10, 90));
    push_decorator(&mut fx.batch, fn_id, "pytest.mark.skip", "pytest.mark.skip");
    let findings = DisabledTestRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.disabled_test");
}

#[test]
fn disabled_test_silent_when_reason_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_thing", range(2, 6, 10, 90));
    push_decorator(
        &mut fx.batch,
        fn_id,
        "pytest.mark.skip",
        "pytest.mark.skip(reason=\"flaky on CI\")",
    );
    assert!(DisabledTestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn disabled_test_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "helper", range(2, 6, 10, 90));
    push_decorator(&mut fx.batch, fn_id, "pytest.mark.skip", "pytest.mark.skip");
    assert!(DisabledTestRule.run(&fx.ctx()).is_empty());
}

// ---------- shared_setup_in_assertion -----------------------------------

/// `(callee_ref, line)` pairs for each setup / assertion call in a
/// top-heavy fixture. One entry per source line — caller drives them
/// through a single iterator dispatch so the `push_call` invocation
/// count stays at one per build_fn (vs. one per row).
const TOP_HEAVY_CALLS: &[(&str, u32)] = &[
    ("setup_a", 2),
    ("setup_b", 3),
    ("setup_c", 4),
    ("setup_d", 5),
    ("setup_e", 6),
    ("setup_f", 7),
    ("setup_g", 8),
    ("setup_h", 9),
    ("assertEqual", 20),
];

/// Build a function with eight setup calls and one trailing assertion.
/// Used by both the positive and the file-gated negative cases of
/// `cc.test.shared_setup_in_assertion`.
fn push_top_heavy_function(fx: &mut Fixture, file: NodeId) -> NodeId {
    let fn_id = push_function(&mut fx.batch, file, "test_top_heavy", range(1, 30, 0, 600));
    for (callee, line) in TOP_HEAVY_CALLS {
        push_call(
            &mut fx.batch,
            fn_id,
            callee,
            range(*line, *line, line * 10, line * 10 + 9),
        );
    }
    fn_id
}

#[test]
fn shared_setup_in_assertion_flags_top_heavy_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let _fn_id = push_top_heavy_function(&mut fx, file);
    let findings = SharedSetupInAssertionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.shared_setup_in_assertion");
}

/// `(callee_ref, line)` pairs for the balanced test fixture: 1 setup
/// + 1 act + 3 assertions. Pre-assertion ratio is 40% — well below the
/// 70% gate, so the rule must stay silent.
const BALANCED_CALLS: &[(&str, u32)] = &[
    ("setup_a", 2),
    ("act_step", 3),
    ("assertEqual", 4),
    ("assertNotEqual", 5),
    ("assertTrue", 6),
];

#[test]
fn shared_setup_in_assertion_silent_for_balanced_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_balanced", range(1, 10, 0, 200));
    for (callee, line) in BALANCED_CALLS {
        push_call(
            &mut fx.batch,
            fn_id,
            callee,
            range(*line, *line, line * 10, line * 10 + 9),
        );
    }
    assert!(SharedSetupInAssertionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn shared_setup_in_assertion_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let _fn_id = push_top_heavy_function(&mut fx, file);
    assert!(SharedSetupInAssertionRule.run(&fx.ctx()).is_empty());
}

// ---------- flaky_iteration ---------------------------------------------

/// Pre-baked source ranges for the flaky-iteration fixture.
/// `[function, loop, inner_call, assertion]` — one constant per slot,
/// so the helper builds the fixture without re-invoking `range()` per
/// node.
const LOOP_FIXTURE_RANGES: [Range; 4] = [
    Range::new(pos(1, 0), pos(10, 200)),
    Range::new(pos(2, 10), pos(8, 180)),
    Range::new(pos(3, 11), pos(3, 30)),
    Range::new(pos(4, 31), pos(4, 50)),
];

/// Build a function containing one [`NodeKind::Loop`] whose body holds
/// `inner_callee` followed by an `assertEqual` call. Returns the
/// function id.
fn push_loop_with_calls(
    fx: &mut Fixture,
    file: NodeId,
    fn_name: &str,
    inner_callee: &str,
) -> NodeId {
    let fn_id = push_function(&mut fx.batch, file, fn_name, LOOP_FIXTURE_RANGES[0]);
    let loop_id = push_loop(&mut fx.batch, fn_id, LOOP_FIXTURE_RANGES[1]);
    push_call(&mut fx.batch, loop_id, inner_callee, LOOP_FIXTURE_RANGES[2]);
    push_call(
        &mut fx.batch,
        loop_id,
        "assertEqual",
        LOOP_FIXTURE_RANGES[3],
    );
    fn_id
}

#[test]
fn flaky_iteration_flags_random_in_loop_with_assert() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let _fn_id = push_loop_with_calls(&mut fx, file, "test_random_loop", "random.random");
    let findings = FlakyIterationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.flaky_iteration");
}

#[test]
fn flaky_iteration_silent_for_deterministic_loop() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let _fn_id = push_loop_with_calls(&mut fx, file, "test_loop", "process");
    assert!(FlakyIterationRule.run(&fx.ctx()).is_empty());
}

#[test]
fn flaky_iteration_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let _fn_id = push_loop_with_calls(&mut fx, file, "loop_helper", "random.random");
    assert!(FlakyIterationRule.run(&fx.ctx()).is_empty());
}

// ---------- assertion_count_zero ----------------------------------------

#[test]
fn assertion_count_zero_flags_test_with_no_assertions() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_empty", range(1, 5, 0, 80));
    push_call(&mut fx.batch, fn_id, "do_thing", range(2, 2, 10, 30));
    let findings = AssertionCountZeroRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.assertion_count_zero");
}

#[test]
fn assertion_count_zero_silent_when_assertion_present() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "test_real", range(1, 5, 0, 80));
    push_call(&mut fx.batch, fn_id, "assertEqual", range(2, 2, 10, 30));
    assert!(AssertionCountZeroRule.run(&fx.ctx()).is_empty());
}

#[test]
fn assertion_count_zero_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    let fn_id = push_function(&mut fx.batch, file, "helper", range(1, 5, 0, 80));
    push_call(&mut fx.batch, fn_id, "do_thing", range(2, 2, 10, 30));
    assert!(AssertionCountZeroRule.run(&fx.ctx()).is_empty());
}

// ---------- test_imports_test_module ------------------------------------

#[test]
fn test_imports_test_module_flags_cross_test_import() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_import(
        &mut fx.batch,
        file,
        "tests.helpers.test_login",
        range(1, 1, 0, 40),
    );
    let findings = TestImportsTestModuleRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.test_imports_test_module");
}

#[test]
fn test_imports_test_module_silent_for_production_import() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_import(&mut fx.batch, file, "myapp.login", range(1, 1, 0, 40));
    assert!(TestImportsTestModuleRule.run(&fx.ctx()).is_empty());
}

#[test]
fn test_imports_test_module_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    push_import(
        &mut fx.batch,
        file,
        "tests.helpers.test_login",
        range(1, 1, 0, 40),
    );
    assert!(TestImportsTestModuleRule.run(&fx.ctx()).is_empty());
}

// ---------- gigantic_test_function --------------------------------------

#[test]
fn gigantic_test_function_flags_long_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_function(&mut fx.batch, file, "test_huge", range(1, 200, 0, 4000));
    let findings = GiganticTestFunctionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "cc.test.gigantic_test_function");
}

#[test]
fn gigantic_test_function_silent_for_short_test() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, TEST_PATH);
    push_function(&mut fx.batch, file, "test_short", range(1, 30, 0, 600));
    assert!(GiganticTestFunctionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gigantic_test_function_silent_outside_test_file() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, NON_TEST_PATH);
    push_function(&mut fx.batch, file, "test_huge", range(1, 200, 0, 4000));
    assert!(GiganticTestFunctionRule.run(&fx.ctx()).is_empty());
}

// ---------- stubs (registration-only) -----------------------------------

#[test]
fn no_negative_case_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(NoNegativeCaseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn private_helper_imported_into_test_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(PrivateHelperImportedIntoTestRule.run(&fx.ctx()).is_empty());
}

#[test]
fn non_isolated_state_stub_returns_empty() {
    let fx = Fixture::new();
    assert!(NonIsolatedStateRule.run(&fx.ctx()).is_empty());
}

// ---------- pt_fixture_returns_value (Phase 11) -------------------------

use crate::pt_assert_in_finally::PtAssertInFinallyRule;
use crate::pt_fixture_returns_value::PtFixtureReturnsValueRule;
use crate::pt_missing_test_classname_prefix::PtMissingTestClassnamePrefixRule;
use crate::pt_parametrize_no_kwargs::PtParametrizeNoKwargsRule;
use crate::pt_raises_simple_block::PtRaisesSimpleBlockRule;

#[test]
fn pt_fixture_returns_value_flags_bare_decorator() {
    let body = "import pytest\n\
                @pytest.fixture\n\
                def user():\n    \
                    return User(\"alice\")\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    let findings = PtFixtureReturnsValueRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.pt_fixture_returns_value");
}

#[test]
fn pt_fixture_returns_value_silent_when_scope_explicit() {
    let body = "import pytest\n\
                @pytest.fixture(scope=\"module\")\n\
                def user():\n    \
                    return User(\"alice\")\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtFixtureReturnsValueRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pt_fixture_returns_value_silent_for_underscore_name() {
    let body = "import pytest\n\
                @pytest.fixture\n\
                def _user():\n    \
                    return User(\"alice\")\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtFixtureReturnsValueRule.run(&fx.ctx()).is_empty());
}

// ---------- pt_parametrize_no_kwargs (Phase 11) -------------------------

#[test]
fn pt_parametrize_no_kwargs_flags_csv_names() {
    let body = "import pytest\n\
                @pytest.mark.parametrize(\"x,y\", [(1, 2)])\n\
                def test_pair(x, y):\n    \
                    assert x + y == 3\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    let findings = PtParametrizeNoKwargsRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.pt_parametrize_no_kwargs");
}

#[test]
fn pt_parametrize_no_kwargs_silent_for_tuple_names() {
    let body = "import pytest\n\
                @pytest.mark.parametrize((\"x\", \"y\"), [(1, 2)])\n\
                def test_pair(x, y):\n    \
                    assert x + y == 3\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtParametrizeNoKwargsRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pt_parametrize_no_kwargs_silent_for_single_name() {
    let body = "import pytest\n\
                @pytest.mark.parametrize(\"x\", [1, 2, 3])\n\
                def test_one(x):\n    \
                    assert x > 0\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtParametrizeNoKwargsRule.run(&fx.ctx()).is_empty());
}

// ---------- pt_raises_simple_block (Phase 11) ---------------------------

#[test]
fn pt_raises_simple_block_flags_multi_statement_body() {
    let body = "import pytest\n\
                def test_thing():\n    \
                    with pytest.raises(ValueError):\n        \
                        x = compute()\n        \
                        do_other(x)\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    let findings = PtRaisesSimpleBlockRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.pt_raises_simple_block");
}

#[test]
fn pt_raises_simple_block_silent_for_single_statement() {
    let body = "import pytest\n\
                def test_thing():\n    \
                    with pytest.raises(ValueError):\n        \
                        compute()\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtRaisesSimpleBlockRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pt_raises_simple_block_silent_outside_test_file() {
    let body = "import pytest\n\
                def helper():\n    \
                    with pytest.raises(ValueError):\n        \
                        x = compute()\n        \
                        do_other(x)\n";
    let mut fx = Fixture::new().with_source(NON_TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, NON_TEST_PATH);
    assert!(PtRaisesSimpleBlockRule.run(&fx.ctx()).is_empty());
}

// ---------- pt_assert_in_finally (Phase 11) -----------------------------

#[test]
fn pt_assert_in_finally_flags_assert_in_finally_block() {
    let body = "def test_thing():\n    \
                    try:\n        \
                        do_thing()\n    \
                    finally:\n        \
                        assert state == 1\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    let findings = PtAssertInFinallyRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.test.pt_assert_in_finally");
}

#[test]
fn pt_assert_in_finally_silent_when_assertion_outside_finally() {
    let body = "def test_thing():\n    \
                    try:\n        \
                        do_thing()\n    \
                    finally:\n        \
                        cleanup()\n    \
                    assert state == 1\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtAssertInFinallyRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pt_assert_in_finally_silent_outside_test_file() {
    let body = "def helper():\n    \
                    try:\n        \
                        do_thing()\n    \
                    finally:\n        \
                        assert state == 1\n";
    let mut fx = Fixture::new().with_source(NON_TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, NON_TEST_PATH);
    assert!(PtAssertInFinallyRule.run(&fx.ctx()).is_empty());
}

// ---------- pt_missing_test_classname_prefix (Phase 11) -----------------

#[test]
fn pt_missing_test_classname_prefix_flags_non_test_class() {
    let body = "class LoginCases:\n    \
                    def test_login_ok(self):\n        \
                        pass\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    let findings = PtMissingTestClassnamePrefixRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.test.pt_missing_test_classname_prefix"
    );
}

#[test]
fn pt_missing_test_classname_prefix_silent_for_test_prefix() {
    let body = "class TestLogin:\n    \
                    def test_login_ok(self):\n        \
                        pass\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtMissingTestClassnamePrefixRule.run(&fx.ctx()).is_empty());
}

#[test]
fn pt_missing_test_classname_prefix_silent_for_private_class() {
    let body = "class _PrivateHelper:\n    \
                    def helper(self):\n        \
                        pass\n";
    let mut fx = Fixture::new().with_source(TEST_PATH, body.as_bytes().to_vec());
    let _ = push_file(&mut fx.batch, TEST_PATH);
    assert!(PtMissingTestClassnamePrefixRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration ----------------------------------------

#[test]
fn builtin_pack_registers_fifteen_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTestDesignPack)
        .expect("Family-28 pack registers without error");
    assert_eq!(reg.rules().count(), 15);
    for slug in [
        "cc.test.unconditional_assert_true",
        "cc.test.disabled_test",
        "cc.test.shared_setup_in_assertion",
        "cc.test.flaky_iteration",
        "cc.test.no_negative_case",
        "cc.test.assertion_count_zero",
        "cc.test.private_helper_imported_into_test",
        "cc.test.non_isolated_state",
        "cc.test.test_imports_test_module",
        "cc.test.gigantic_test_function",
        // Phase 11 — pytest PT-family.
        "cc.test.pt_fixture_returns_value",
        "cc.test.pt_parametrize_no_kwargs",
        "cc.test.pt_raises_simple_block",
        "cc.test.pt_assert_in_finally",
        "cc.test.pt_missing_test_classname_prefix",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
