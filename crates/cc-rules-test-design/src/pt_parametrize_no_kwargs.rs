//! `cc.test.pt_parametrize_no_kwargs` — `@pytest.mark.parametrize`
//! invoked with a CSV string of parameter names instead of a tuple.
//!
//! Mirrors ruff PT006. The form
//!
//! ```python
//! @pytest.mark.parametrize("x,y", [(1, 2)])
//! ```
//!
//! is brittle: pytest splits on `,` so adding a name with a comma in a
//! type annotation, default value, or `Tuple[int, int]` breaks silently.
//! The tuple form
//!
//! ```python
//! @pytest.mark.parametrize(("x", "y"), [(1, 2)])
//! ```
//!
//! is unambiguous.
//!
//! Phase-10 source-byte detector: `.py` files only, scan every line for
//! `@pytest.mark.parametrize("...,...",` shape — the first positional
//! arg must be a string literal that contains `,`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.pt_parametrize_no_kwargs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtParametrizeNoKwargsRule;

const NEEDLES: &[&str] = &["@pytest.mark.parametrize(", "pytest.mark.parametrize("];

impl Rule for PtParametrizeNoKwargsRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.pt_parametrize_no_kwargs"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`@pytest.mark.parametrize(\"x,y\", ...)` should pass a tuple of names"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if !is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
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
        if let Some(arg) = find_csv_first_arg(line) {
            out.push(emit(path.clone(), idx + 1, line, arg));
        }
    }
}

/// Return the CSV string when the first positional argument to
/// `@pytest.mark.parametrize(...)` is a quoted string literal that
/// contains a comma.
fn find_csv_first_arg(line: &str) -> Option<String> {
    for needle in NEEDLES {
        let Some(pos) = line.find(needle) else {
            continue;
        };
        let after = &line[pos + needle.len()..];
        let after_trim = after.trim_start();
        if let Some(payload) = first_string_literal(after_trim) {
            if payload.contains(',') {
                return Some(payload);
            }
        }
    }
    None
}

/// Extract the contents of the first quoted string literal at the start
/// of `s` (single or double quotes). Returns `None` for any other shape.
fn first_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &bytes[1..];
    let end = rest.iter().position(|b| *b == quote)?;
    std::str::from_utf8(&rest[..end]).ok().map(str::to_owned)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, csv: String) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let names: Vec<String> = csv
        .split(',')
        .map(|s| format!("\"{}\"", s.trim()))
        .collect();
    let suggestion = format!("({})", names.join(", "));
    build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.pt_parametrize_no_kwargs",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "`@pytest.mark.parametrize(\"{csv}\", ...)` uses a CSV \
             instead of a tuple of names"
        ),
        explanation: "Pytest splits the CSV form on `,` to recover individual \
             parameter names. The split is structural: a name with a \
             trailing comment, a default value, or a generic argument \
             like `Tuple[int, int]` will tear at the wrong boundary. The \
             tuple-of-names form is unambiguous and survives all of \
             these refactors."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace the CSV string with a tuple of names: {suggestion}. \
             For a single parameter, prefer the bare string \
             form (`\"x\"`) — pytest treats that as the single-name case."
        )),
        snippet,
        weight: 1,
    })
}
