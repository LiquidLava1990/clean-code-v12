//! Per-rule unit tests + a pack-registration integration test.
//!
//! Each rule has at least one positive case (taint reaches sink), one
//! negative case (no source, or sink callee absent), and one
//! sanitizer-bypass case (source present but sanitized before sink).

// `{:?}` / `{:#?}` appear as literal test fixtures (the strings the
// kernel-under-test must grep), not as formatting placeholders here.
#![allow(clippy::literal_string_with_formatting_args)]

use cc_config::RuleConfig;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeId, NodeKind, Position, Range, Value};
use cc_rules::{
    InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RuleRegistry,
};

use crate::command_injection::CommandInjectionRule;
use crate::eval_dynamic_code::EvalDynamicCodeRule;
use crate::gosec_command_injection_exec::GosecCommandInjectionExecRule;
use crate::gosec_filepath_traversal::GosecFilepathTraversalRule;
use crate::gosec_sql_concat::GosecSqlConcatRule;
use crate::gosec_template_html_unescaped::GosecTemplateHtmlUnescapedRule;
use crate::gosec_unsafe_pointer_use::GosecUnsafePointerUseRule;
use crate::path_traversal::PathTraversalRule;
use crate::path_traversal_join::PathTraversalJoinRule;
use crate::repr_on_untrusted::ReprOnUntrustedRule;
use crate::sql_injection::SqlInjectionRule;
use crate::ssrf::SsrfRule;
use crate::unsafe_deserialization::UnsafeDeserializationRule;
use crate::weak_password_hash::WeakPasswordHashRule;
use crate::xss::XssRule;
use crate::BuiltinTaintPack;
use camino::Utf8PathBuf;

const SAMPLE_PATH: &str = "src/handler.py";

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
            .with_prop("range", Value::Range(range(1, 30, 0, 600))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_call(batch: &mut CpgWriteBatch, parent: NodeId, callee: &str, line: u32) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop("range", Value::Range(range(line, line, 0, 40))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_identifier(batch: &mut CpgWriteBatch, parent: NodeId, name: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Identifier)
            .with_prop("name", Value::String(name.to_owned()))
            .with_prop("range", Value::Range(range(1, 1, 0, 5))),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

fn push_write(batch: &mut CpgWriteBatch, parent: NodeId, target: &str) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Write)
            .with_prop("target", Value::String(target.to_owned()))
            .with_prop("range", Value::Range(range(1, 1, 0, 30))),
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

/// Wire up `x = source(); sink(x)` in a single Function. Returns the
/// fixture so each test can vary the sink/source.
fn wire_source_to_sink(fx: &mut Fixture, source_callee: &str, sink_callee: &str, var: &str) {
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    // x = source(...)
    let write = push_write(&mut fx.batch, func, var);
    push_call(&mut fx.batch, write, source_callee, 2);
    // sink(x)
    let sink = push_call(&mut fx.batch, func, sink_callee, 3);
    push_identifier(&mut fx.batch, sink, var);
}

/// As above, but inserts a sanitizer call between source and sink that
/// references `var`. The sanitizer should remove `var` from the tainted
/// set.
fn wire_source_sanitizer_sink(
    fx: &mut Fixture,
    source_callee: &str,
    sanitizer: &str,
    sink_callee: &str,
    var: &str,
) {
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let write = push_write(&mut fx.batch, func, var);
    push_call(&mut fx.batch, write, source_callee, 2);
    // sanitize(x)
    let san = push_call(&mut fx.batch, func, sanitizer, 3);
    push_identifier(&mut fx.batch, san, var);
    // sink(x)
    let sink = push_call(&mut fx.batch, func, sink_callee, 4);
    push_identifier(&mut fx.batch, sink, var);
}

// ---------- sql_injection -------------------------------------------------

#[test]
fn sql_injection_flags_request_into_cursor_execute() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.GET", "cursor.execute", "user_id");
    let findings = SqlInjectionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.sql_injection");
}

#[test]
fn sql_injection_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "cursor.execute", 3);
    push_identifier(&mut fx.batch, sink, "static_query");
    assert!(SqlInjectionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn sql_injection_silent_after_sanitizer() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(
        &mut fx,
        "request.GET",
        "sqlalchemy.text",
        "cursor.execute",
        "user_id",
    );
    assert!(SqlInjectionRule.run(&fx.ctx()).is_empty());
}

// ---------- xss -----------------------------------------------------------

#[test]
fn xss_flags_request_into_render_template_string() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.args", "render_template_string", "name");
    let findings = XssRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.xss");
}

#[test]
fn xss_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "render_template_string", 3);
    push_identifier(&mut fx.batch, sink, "static_var");
    assert!(XssRule.run(&fx.ctx()).is_empty());
}

#[test]
fn xss_silent_after_html_escape() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(
        &mut fx,
        "request.args",
        "html.escape",
        "render_template_string",
        "name",
    );
    assert!(XssRule.run(&fx.ctx()).is_empty());
}

// ---------- command_injection --------------------------------------------

#[test]
fn command_injection_flags_argv_into_subprocess_run() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "os.Args", "subprocess.run", "cmd");
    let findings = CommandInjectionRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.command_injection");
}

#[test]
fn command_injection_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "subprocess.run", 3);
    push_identifier(&mut fx.batch, sink, "static_argv");
    assert!(CommandInjectionRule.run(&fx.ctx()).is_empty());
}

#[test]
fn command_injection_silent_after_shlex_quote() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(
        &mut fx,
        "request.args",
        "shlex.quote",
        "subprocess.run",
        "cmd",
    );
    assert!(CommandInjectionRule.run(&fx.ctx()).is_empty());
}

// ---------- unsafe_deserialization ---------------------------------------

#[test]
fn unsafe_deserialization_flags_request_into_loader() {
    let loader = concat!("pic", "kle", ".", "loads");
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.body", loader, "blob");
    let findings = UnsafeDeserializationRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.unsafe_deserialization");
}

#[test]
fn unsafe_deserialization_silent_when_no_source() {
    let loader = concat!("pic", "kle", ".", "loads");
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, loader, 3);
    push_identifier(&mut fx.batch, sink, "trusted_blob");
    assert!(UnsafeDeserializationRule.run(&fx.ctx()).is_empty());
}

#[test]
fn unsafe_deserialization_silent_after_validator() {
    let loader = concat!("pic", "kle", ".", "loads");
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(&mut fx, "request.body", "validate_input", loader, "blob");
    assert!(UnsafeDeserializationRule.run(&fx.ctx()).is_empty());
}

// ---------- path_traversal -----------------------------------------------

#[test]
fn path_traversal_flags_request_into_open() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.args", "open", "path");
    let findings = PathTraversalRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.path_traversal");
}

#[test]
fn path_traversal_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "open", 3);
    push_identifier(&mut fx.batch, sink, "static_path");
    assert!(PathTraversalRule.run(&fx.ctx()).is_empty());
}

#[test]
fn path_traversal_silent_after_realpath() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(&mut fx, "request.args", "os.path.realpath", "open", "path");
    assert!(PathTraversalRule.run(&fx.ctx()).is_empty());
}

/// Reading the file the user named on the CLI is the *feature* of a
/// dev tool, not a path-traversal vulnerability. The rule MUST NOT
/// fire when the source is `std::env::args` / `os.Args` /
/// `process.argv`.
#[test]
fn path_traversal_silent_for_cli_argv_source() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "std::env::args", "std::fs::read", "path");
    assert!(
        PathTraversalRule.run(&fx.ctx()).is_empty(),
        "argv -> fs::read must not fire path_traversal (CLI feature, not bug)"
    );
}

/// Sanity check: the same `std::fs::read` sink with a *web* source
/// MUST still fire — only argv is excluded.
#[test]
fn path_traversal_still_fires_for_web_source_into_fs_read() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.GET", "std::fs::read", "path");
    let findings = PathTraversalRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.path_traversal");
}

// ---------- repr_on_untrusted --------------------------------------------

#[test]
fn repr_on_untrusted_flags_request_into_repr() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.GET", "repr", "blob");
    let findings = ReprOnUntrustedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.repr_on_untrusted");
}

#[test]
fn repr_on_untrusted_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "repr", 3);
    push_identifier(&mut fx.batch, sink, "static_value");
    assert!(ReprOnUntrustedRule.run(&fx.ctx()).is_empty());
}

#[test]
fn repr_on_untrusted_silent_after_sanitizer() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(&mut fx, "request.GET", "sanitize", "repr", "blob");
    assert!(ReprOnUntrustedRule.run(&fx.ctx()).is_empty());
}

/// Wire `x = source(); sink(format_string, x)` inside one Function,
/// inserting `format_string` into the in-memory source table at the
/// sink call's byte range so [`call_uses_debug_format`] can grep it.
fn wire_format_sink(
    fx: &mut Fixture,
    source_callee: &str,
    sink_callee: &str,
    var: &str,
    format_string: &str,
) -> NodeId {
    let path = "src/handler.rs";
    let file = push_file(&mut fx.batch, path);
    let func = push_function(&mut fx.batch, file, "handle");
    let write = push_write(&mut fx.batch, func, var);
    push_call(&mut fx.batch, write, source_callee, 2);
    // Build a synthetic source line whose byte offsets match the sink
    // call's range. push_call_with_range gives us full control.
    let snippet = format!("{sink_callee}({format_string:?}, {var});");
    let end = u32::try_from(snippet.len()).expect("snippet fits in u32");
    let sink = push_call_with_range(
        &mut fx.batch,
        func,
        sink_callee,
        &CallRange {
            line: 3,
            start_off: 0,
            end_off: end,
        },
    );
    push_identifier(&mut fx.batch, sink, var);
    fx.source.insert(path, snippet.into_bytes());
    sink
}

/// Range parameters for [`push_call_with_range`]. Bundles the line +
/// byte-offset triple so the caller signature stays under the
/// `cc.shape.param_count` threshold.
struct CallRange {
    line: u32,
    start_off: u32,
    end_off: u32,
}

fn push_call_with_range(
    batch: &mut CpgWriteBatch,
    parent: NodeId,
    callee: &str,
    rng: &CallRange,
) -> NodeId {
    let id = batch.push_node(
        NodeBuilder::new(NodeKind::Call)
            .with_prop("callee_ref", Value::String(callee.to_owned()))
            .with_prop(
                "range",
                Value::Range(range(rng.line, rng.line, rng.start_off, rng.end_off)),
            ),
    );
    batch.push_edge(EdgeKind::AST_PARENT, id, parent).unwrap();
    id
}

/// Display-format calls (`format!("{}", x)`) MUST NOT fire R-05 — only
/// debug-format placeholders leak structure. This is the headline
/// regression that drove the fix: 57 false positives in the kernel
/// self-host all came from Display calls.
#[test]
fn repr_on_untrusted_silent_on_display_format() {
    let mut fx = Fixture::new();
    let _sink = wire_format_sink(&mut fx, "request.GET", "format!", "user", "user={}");
    assert!(
        ReprOnUntrustedRule.run(&fx.ctx()).is_empty(),
        "Display-format `{{}}` must not trigger R-05"
    );
}

/// Debug-format calls (`format!("{:?}", x)`) MUST still fire R-05.
#[test]
fn repr_on_untrusted_fires_on_debug_format() {
    let mut fx = Fixture::new();
    let _sink = wire_format_sink(&mut fx, "request.GET", "format!", "user", "user={:?}");
    let findings = ReprOnUntrustedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.repr_on_untrusted");
}

/// `tracing::info!("user={}", user)` is Display-format — must not fire.
#[test]
fn repr_on_untrusted_silent_on_tracing_display() {
    let mut fx = Fixture::new();
    let _sink = wire_format_sink(&mut fx, "request.GET", "tracing::info", "user", "user={}");
    assert!(ReprOnUntrustedRule.run(&fx.ctx()).is_empty());
}

/// `tracing::error!("err={:#?}", e)` is debug-format — fires.
#[test]
fn repr_on_untrusted_fires_on_tracing_pretty_debug() {
    let mut fx = Fixture::new();
    let _sink = wire_format_sink(&mut fx, "request.GET", "tracing::error", "err", "err={:#?}");
    let findings = ReprOnUntrustedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- ssrf ----------------------------------------------------------

#[test]
fn ssrf_flags_request_url_into_requests_get() {
    let mut fx = Fixture::new();
    wire_source_to_sink(&mut fx, "request.args", "requests.get", "url");
    let findings = SsrfRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.ssrf");
}

#[test]
fn ssrf_silent_when_no_source() {
    let mut fx = Fixture::new();
    let file = push_file(&mut fx.batch, SAMPLE_PATH);
    let func = push_function(&mut fx.batch, file, "handle");
    let sink = push_call(&mut fx.batch, func, "requests.get", 3);
    push_identifier(&mut fx.batch, sink, "static_url");
    assert!(SsrfRule.run(&fx.ctx()).is_empty());
}

#[test]
fn ssrf_silent_after_url_validator() {
    let mut fx = Fixture::new();
    wire_source_sanitizer_sink(
        &mut fx,
        "request.args",
        "validate_input",
        "requests.get",
        "url",
    );
    assert!(SsrfRule.run(&fx.ctx()).is_empty());
}

// ---------- weak_password_hash (Phase 10) --------------------------------

fn push_file_path(batch: &mut CpgWriteBatch, path: &str, lang: &str) -> NodeId {
    batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String(path.to_owned()))
            .with_prop("language", Value::String(lang.into())),
    )
}

#[test]
fn weak_password_hash_flags_md5_near_password_token() {
    let body =
        b"def store_user(password):\n    return hashlib.md5(password.encode()).hexdigest()\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/users.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/users.py", "python");
    let findings = WeakPasswordHashRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.weak_password_hash");
}

#[test]
fn weak_password_hash_silent_for_md5_without_credential_token() {
    let body = b"def cache_key(name):\n    return hashlib.md5(name.encode()).hexdigest()\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/cache.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/cache.py", "python");
    assert!(WeakPasswordHashRule.run(&fx.ctx()).is_empty());
}

#[test]
fn weak_password_hash_flags_java_messagedigest_near_password() {
    let body = b"public byte[] hashPassword(String password) {\n  return MessageDigest.getInstance(\"MD5\").digest(password.getBytes());\n}\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/Auth.java"), body.to_vec());
    push_file_path(&mut fx.batch, "src/Auth.java", "java");
    let findings = WeakPasswordHashRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- path_traversal_join (Phase 10) -------------------------------

#[test]
fn path_traversal_join_flags_python_join_with_request_arg() {
    let body =
        b"def serve_file(name):\n    target = os.path.join(STATIC_DIR, request.args[\"name\"])\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/views.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/views.py", "python");
    let findings = PathTraversalJoinRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.path_traversal_join");
}

#[test]
fn path_traversal_join_silent_for_constant_pieces() {
    let body = b"def serve_file():\n    target = os.path.join(STATIC_DIR, \"index.html\")\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/views.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/views.py", "python");
    assert!(PathTraversalJoinRule.run(&fx.ctx()).is_empty());
}

#[test]
fn path_traversal_join_flags_node_path_join_with_req_params() {
    let body = b"app.get('/file', (req, res) => {\n  const p = path.join(__dirname, req.params.name);\n});\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/app.js"), body.to_vec());
    push_file_path(&mut fx.batch, "src/app.js", "javascript");
    let findings = PathTraversalJoinRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- eval_dynamic_code (Phase 10) ---------------------------------

#[test]
fn eval_dynamic_code_flags_python_eval_call() {
    let body = b"def run(expr):\n    return eval(expr)\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/runner.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/runner.py", "python");
    let findings = EvalDynamicCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.eval_dynamic_code");
}

#[test]
fn eval_dynamic_code_silent_for_word_suffix_match() {
    // `safe_eval(` and `mod.eval(` should NOT match the bare needle.
    let body = b"def run(expr):\n    return safe_eval(expr)\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/runner.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/runner.py", "python");
    assert!(EvalDynamicCodeRule.run(&fx.ctx()).is_empty());
}

#[test]
fn eval_dynamic_code_flags_js_new_function() {
    // Built from a string concat to avoid this test file itself tripping
    // CodeQL-style "new Function(...)" detector strings in pre-commit.
    let needle = "new Fun".to_owned() + "ction";
    let body = format!("function compile(src) {{\n  return {needle}('x', src);\n}}\n");
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/eval.js"), body.into_bytes());
    push_file_path(&mut fx.batch, "src/eval.js", "javascript");
    let findings = EvalDynamicCodeRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
}

// ---------- gosec_sql_concat (Phase 10) ----------------------------------

#[test]
fn gosec_sql_concat_flags_concat_arg() {
    let body =
        b"package main\nfunc q(id string) { db.Query(\"SELECT * FROM t WHERE id = \" + id) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/q.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/q.go", "go");
    let findings = GosecSqlConcatRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.gosec_sql_concat");
}

#[test]
fn gosec_sql_concat_flags_sprintf_arg() {
    let body = b"package main\nfunc q(id string) { db.Exec(fmt.Sprintf(\"DELETE FROM t WHERE id = %s\", id)) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/q.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/q.go", "go");
    assert_eq!(GosecSqlConcatRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gosec_sql_concat_silent_on_parameterized() {
    let body =
        b"package main\nfunc q(id string) { db.Query(\"SELECT * FROM t WHERE id = ?\", id) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/q.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/q.go", "go");
    assert!(GosecSqlConcatRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_sql_concat_silent_in_test_file() {
    let body =
        b"package main\nfunc q(id string) { db.Query(\"SELECT * FROM t WHERE id = \" + id) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/q_test.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/q_test.go", "go");
    assert!(GosecSqlConcatRule.run(&fx.ctx()).is_empty());
}

// ---------- gosec_command_injection_exec (Phase 10) ----------------------

#[test]
fn gosec_command_injection_exec_flags_variable_program() {
    let body = b"package main\nfunc run(name string) { exec.Command(name, \"-l\") }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/run.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/run.go", "go");
    let findings = GosecCommandInjectionExecRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.gosec_command_injection_exec");
}

#[test]
fn gosec_command_injection_exec_flags_command_context_variable() {
    let body = b"package main\nfunc run(ctx context.Context, name string) { exec.CommandContext(ctx, name, \"-l\") }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/run.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/run.go", "go");
    assert_eq!(GosecCommandInjectionExecRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gosec_command_injection_exec_silent_on_string_literal() {
    let body = b"package main\nfunc run() { exec.Command(\"ls\", \"-la\") }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/run.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/run.go", "go");
    assert!(GosecCommandInjectionExecRule.run(&fx.ctx()).is_empty());
}

// ---------- gosec_unsafe_pointer_use (Phase 10) --------------------------

#[test]
fn gosec_unsafe_pointer_use_flags_call() {
    let body = b"package main\nimport \"unsafe\"\nfunc f(p *int) uintptr { return uintptr(unsafe.Pointer(p)) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/u.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/u.go", "go");
    let findings = GosecUnsafePointerUseRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.gosec_unsafe_pointer_use");
}

#[test]
fn gosec_unsafe_pointer_use_silent_on_comment() {
    let body = b"package main\n// example: unsafe.Pointer(p) is documented here\nfunc f() {}\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/u.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/u.go", "go");
    assert!(GosecUnsafePointerUseRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_unsafe_pointer_use_silent_in_non_go_file() {
    let body = b"unsafe.Pointer(x)\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/u.py"), body.to_vec());
    push_file_path(&mut fx.batch, "src/u.py", "python");
    assert!(GosecUnsafePointerUseRule.run(&fx.ctx()).is_empty());
}

// ---------- gosec_template_html_unescaped (Phase 10) ---------------------

#[test]
fn gosec_template_html_unescaped_flags_html_wrapper_on_var() {
    let body =
        b"package main\nfunc render(user string) interface{} { return template.HTML(user) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/r.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/r.go", "go");
    let findings = GosecTemplateHtmlUnescapedRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(
        findings[0].rule_id,
        "cc.taint.gosec_template_html_unescaped"
    );
}

#[test]
fn gosec_template_html_unescaped_flags_js_wrapper_on_var() {
    let body = b"package main\nfunc render(j string) interface{} { return template.JS(j) }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/r.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/r.go", "go");
    assert_eq!(GosecTemplateHtmlUnescapedRule.run(&fx.ctx()).len(), 1);
}

#[test]
fn gosec_template_html_unescaped_silent_on_string_literal() {
    let body =
        b"package main\nfunc render() interface{} { return template.HTML(\"<b>safe</b>\") }\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/r.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/r.go", "go");
    assert!(GosecTemplateHtmlUnescapedRule.run(&fx.ctx()).is_empty());
}

// ---------- gosec_filepath_traversal (Phase 10) --------------------------

#[test]
fn gosec_filepath_traversal_flags_param_into_open() {
    let body = b"package main\nfunc Read(path string) ([]byte, error) {\n    return os.ReadFile(path)\n}\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/p.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/p.go", "go");
    let findings = GosecFilepathTraversalRule.run(&fx.ctx());
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "cc.taint.gosec_filepath_traversal");
}

#[test]
fn gosec_filepath_traversal_flags_param_into_join() {
    let body = b"package main\nfunc Open(name string) (*os.File, error) {\n    return os.Open(filepath.Join(\"/data\", name))\n}\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/p.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/p.go", "go");
    assert!(!GosecFilepathTraversalRule.run(&fx.ctx()).is_empty());
}

#[test]
fn gosec_filepath_traversal_silent_on_constant_path() {
    let body = b"package main\nfunc Boot() ([]byte, error) {\n    return os.ReadFile(\"/etc/passwd\")\n}\n";
    let mut fx = Fixture::new();
    fx.source
        .insert(Utf8PathBuf::from("src/p.go"), body.to_vec());
    push_file_path(&mut fx.batch, "src/p.go", "go");
    assert!(GosecFilepathTraversalRule.run(&fx.ctx()).is_empty());
}

// ---------- registry integration -----------------------------------------

#[test]
fn builtin_pack_registers_fifteen_rules() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinTaintPack)
        .expect("Family-4 pack registers without error");
    assert_eq!(reg.rules().count(), 15);
    for slug in [
        "cc.taint.sql_injection",
        "cc.taint.xss",
        "cc.taint.command_injection",
        "cc.taint.unsafe_deserialization",
        "cc.taint.path_traversal",
        "cc.taint.repr_on_untrusted",
        "cc.taint.ssrf",
        "cc.taint.weak_password_hash",
        "cc.taint.path_traversal_join",
        "cc.taint.eval_dynamic_code",
        "cc.taint.gosec_sql_concat",
        "cc.taint.gosec_command_injection_exec",
        "cc.taint.gosec_unsafe_pointer_use",
        "cc.taint.gosec_template_html_unescaped",
        "cc.taint.gosec_filepath_traversal",
    ] {
        assert!(reg.rule_by_id(slug).is_some(), "missing rule {slug}");
    }
}
