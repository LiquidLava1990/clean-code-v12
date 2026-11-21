//! `cc.taint.gosec_filepath_traversal` — Go
//! `os.Open(filepath.Join(userInput, ...))` /
//! `ioutil.ReadFile(userInput)` / `os.ReadFile(userInput)` where
//! `userInput` is a function parameter.
//!
//! Mirrors [gosec G304] (`File path provided as taint input`). Reading
//! a path supplied by the caller is the canonical Go path-traversal
//! shape — even with `filepath.Join`, `..` segments climb out of any
//! intended root.
//!
//! Detection: source-byte scan that builds a per-function parameter
//! list (parses `func name(...)` headers) and flags any `os.Open(...)`,
//! `os.OpenFile(...)`, `os.ReadFile(...)`, `ioutil.ReadFile(...)`,
//! `os.Create(...)`, `filepath.Join(...)` whose first arg references
//! one of the parameters.
//!
//! [gosec G304]: https://github.com/securego/gosec/blob/master/rules/readfile.go

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::_go_syntax::first_arg_slice;
use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

const SINK_NEEDLES: &[&str] = &[
    "os.Open(",
    "os.OpenFile(",
    "os.Create(",
    "os.ReadFile(",
    "ioutil.ReadFile(",
    "filepath.Join(",
];

/// Family-4 probe `cc.taint.gosec_filepath_traversal`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecFilepathTraversalRule;

impl Rule for GosecFilepathTraversalRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.gosec_filepath_traversal"
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
        "Go file open/read called with a function parameter (gosec G304)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_go_source(&path) {
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

fn is_go_source(path: &Utf8PathBuf) -> bool {
    let ext_ok = path.extension().map(str::to_ascii_lowercase).as_deref() == Some("go");
    if !ext_ok {
        return false;
    }
    !path
        .file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut current_params: Vec<String> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(params) = extract_func_params(line) {
            current_params = params;
            continue;
        }
        if line.trim_start().starts_with('}') && !current_params.is_empty() {
            current_params.clear();
            continue;
        }
        if current_params.is_empty() {
            continue;
        }
        for needle in matched_sinks(line) {
            if let Some(param) = first_arg_uses_param(line, needle, &current_params) {
                out.push(emit(path.clone(), idx + 1, line, needle, &param));
            }
        }
    }
}

/// Parse `func [recv] Name(p1 T1, p2 T2, ...)` from a single line and
/// return the parameter names. Returns `None` if `line` is not a
/// function declaration.
fn extract_func_params(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("func") {
        return None;
    }
    let open = trimmed.find('(')?;
    let between = &trimmed[..open];
    // Receiver-form `func (r *T) Name(args)` has whitespace between
    // `func` and the first `(`, no identifier. Plain form
    // `func Name(args)` has the identifier between them.
    let is_receiver_form = between.trim() == "func";
    let header = if is_receiver_form {
        let close = trimmed[open + 1..].find(')')?;
        let next_open = trimmed[open + 1 + close + 1..].find('(')?;
        let abs_open = open + 1 + close + 1 + next_open;
        let abs_close = trimmed[abs_open + 1..].find(')')?;
        &trimmed[abs_open + 1..abs_open + 1 + abs_close]
    } else {
        let close = trimmed[open + 1..].find(')')?;
        &trimmed[open + 1..open + 1 + close]
    };
    Some(parse_param_names(header))
}

/// Split `name1 type1, name2 type2, name3 name4 type3` and return the
/// identifiers (never the trailing types).
fn parse_param_names(s: &str) -> Vec<String> {
    let mut names = Vec::new();
    for group in s.split(',') {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }
        let parts: Vec<&str> = group.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        // Last token is the type; everything before is shared names.
        for part in &parts[..parts.len() - 1] {
            let cleaned = part.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
            if !cleaned.is_empty() && !cleaned.starts_with(char::is_numeric) {
                names.push(cleaned.to_owned());
            }
        }
    }
    names
}

fn matched_sinks(line: &str) -> Vec<&'static str> {
    SINK_NEEDLES
        .iter()
        .copied()
        .filter(|n| line.contains(n))
        .collect()
}

fn first_arg_uses_param(line: &str, needle: &str, params: &[String]) -> Option<String> {
    let pos = line.find(needle)?;
    let after = &line[pos + needle.len()..];
    let arg = first_arg_slice(after);
    for param in params {
        if identifier_appears(arg, param) {
            return Some(param.clone());
        }
    }
    None
}

/// True iff `name` appears as a stand-alone identifier in `s` (bounded
/// by non-name characters on both sides).
fn identifier_appears(s: &str, name: &str) -> bool {
    let bytes = s.as_bytes();
    let n = name.as_bytes();
    if n.is_empty() || n.len() > bytes.len() {
        return false;
    }
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        if &bytes[i..i + n.len()] == n
            && left_boundary(bytes, i)
            && right_boundary(bytes, i + n.len())
        {
            return true;
        }
        i += 1;
    }
    false
}

fn left_boundary(bytes: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let prev = bytes[i - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_' && prev != b'.'
}

fn right_boundary(bytes: &[u8], end: usize) -> bool {
    if end >= bytes.len() {
        return true;
    }
    let next = bytes[end];
    !next.is_ascii_alphanumeric() && next != b'_'
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, sink: &str, param: &str) -> Finding {
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
        rule_id: "cc.taint.gosec_filepath_traversal",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`{}` reads a path derived from caller-controlled parameter `{param}` (gosec G304)",
            sink.trim_end_matches('('),
        ),
        explanation: "A function parameter is flowing directly into a \
             filesystem path API. gosec G304 catches this pattern: even \
             with `filepath.Join(root, p)`, a `..` segment escapes the \
             intended root. Reading the file the caller named is fine \
             for a CLI tool but a path-traversal bug in a server."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Canonicalize the resolved path with `filepath.Clean` + \
             `filepath.Abs`, then assert it has the expected root as a \
             prefix before opening. Reject any input containing `..`."
                .into(),
        ),
        snippet,
        weight: 6,
    })
}
