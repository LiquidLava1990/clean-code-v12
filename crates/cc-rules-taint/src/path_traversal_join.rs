//! `cc.taint.path_traversal_join` — `os.path.join(BASE, user_input)` /
//! `path.join(BASE, req.params.x)` style join of an upper-case-named base
//! with an HTTP-derived input. The pattern is the classic path-traversal
//! footgun that survives every "but I prefixed it with my safe root!"
//! rationale: `path.join("/safe", "../etc/passwd")` resolves to
//! `/etc/passwd` on every mainstream platform.
//!
//! Sister probe to [`crate::path_traversal`] — the existing taint rule
//! catches the *value-flow* version (request → fs.open). This probe
//! catches the *syntactic* version visible at a glance on a single line:
//!
//! - **Python**: `os.path.join(BASE, request.args["x"])`,
//!   `os.path.join(ROOT, req.body.path)`, `Path(BASE) / user_input`.
//! - **JavaScript / TypeScript**: `path.join(BASE, req.params.x)`,
//!   `path.join(__dirname, req.query.name)`.
//!
//! OSS source: CodeQL `py/path-injection`, Sonar `python:S2083`,
//! Semgrep `python.lang.security.audit.path-traversal`,
//! `javascript.express.security.audit.path-traversal-join`.
//!
//! Phase-10 source-byte heuristic: scan for `os.path.join(` /
//! `path.join(` whose argument list contains both an upper-case-only
//! base identifier (`BASE`, `ROOT`, `STATIC_DIR`, `__dirname`) AND a
//! request-shaped expression (`req.body`, `req.params`, `req.query`,
//! `request.args`, `request.json`, `request.form`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

/// Family-4 probe `cc.taint.path_traversal_join`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PathTraversalJoinRule;

const SUPPORTED_EXTS: &[&str] = &["py", "js", "jsx", "ts", "tsx", "mjs", "cjs"];

const JOIN_NEEDLES: &[&str] = &[
    "os.path.join(",
    "path.join(",
    "posixpath.join(",
    "ntpath.join(",
];

const REQUEST_TOKENS: &[&str] = &[
    "req.body",
    "req.params",
    "req.query",
    "request.args",
    "request.json",
    "request.form",
    "request.params",
    "request.values",
    "request.GET",
    "request.POST",
];

const SAFE_BASE_NEEDLES: &[&str] = &[
    "BASE",
    "ROOT",
    "STATIC_DIR",
    "STATIC_ROOT",
    "DATA_DIR",
    "UPLOAD_DIR",
    "STORAGE_DIR",
    "__dirname",
    "process.cwd()",
    "os.getcwd()",
];

impl Rule for PathTraversalJoinRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.path_traversal_join"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "path.join(BASE, user_input) — request data joined to a known root without sanitization"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_ext(&path) {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_supported_ext(path: &Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| SUPPORTED_EXTS.iter().any(|e| *e == ext))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if !contains_join(line) {
            continue;
        }
        if !contains_safe_base(line) {
            continue;
        }
        if let Some(token) = matched_request_token(line) {
            out.push(emit(path.clone(), idx + 1, line, token));
        }
    }
}

fn contains_join(line: &str) -> bool {
    JOIN_NEEDLES.iter().any(|n| line.contains(n))
}

fn contains_safe_base(line: &str) -> bool {
    SAFE_BASE_NEEDLES.iter().any(|n| line.contains(n))
}

fn matched_request_token(line: &str) -> Option<&'static str> {
    REQUEST_TOKENS.iter().copied().find(|t| line.contains(t))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, token: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TaintFindingBlueprint {
        rule_id: "cc.taint.path_traversal_join",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "path-join with request input `{token}` and a known root — \
             `..` segments escape the root"
        ),
        explanation: "`os.path.join` / `path.join` does not sanitize: \
             `path.join(\"/safe\", \"../etc/passwd\")` resolves to \
             `/etc/passwd`. Joining a request-derived value to an \
             upper-case-named base directory is the classic path-traversal \
             pattern. The base feels like a guard rail; it isn't."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Canonicalise the result via `os.path.realpath` / \
             `path.resolve` and assert it sits under the intended root \
             (string-prefix check on the canonical form). Reject any \
             input containing `..`. Better yet, look the user value up \
             in an allow-list keyed mapping rather than feeding it to \
             the filesystem."
                .into(),
        ),
        snippet,
        weight: 6,
    })
}
