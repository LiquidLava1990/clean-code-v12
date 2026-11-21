//! `cc.modernize.python_dataclass_for_class_with_init` — Python class
//! whose `__init__` only assigns parameters straight to `self`.
//!
//! ```python
//! class User:
//!     def __init__(self, name: str, age: int, email: str) -> None:
//!         self.name = name
//!         self.age = age
//!         self.email = email
//! ```
//! `@dataclass` (Python 3.7+) auto-generates `__init__`, `__repr__`,
//! and `__eq__` from class-level type annotations:
//! ```python
//! @dataclass
//! class User:
//!     name: str
//!     age: int
//!     email: str
//! ```
//! Removes nine lines of boilerplate and gains free `__repr__` /
//! `__eq__`. Severity::Nit (the un-dataclass form is correct, just
//! verbose).
//!
//! OSS source: ruff `D` family + Python community refactor playbooks.
//!
//! Phase-12 source-byte heuristic: `.py` files only. Find every `class`
//! definition; its body must contain a `def __init__(self, ...)` whose
//! body is N consecutive `self.<x> = <x>` lines (N ≥ 2). Skip classes
//! that already carry a `@dataclass` (or any `@dataclasses.*`)
//! decorator on the line immediately above the `class` header.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.python_dataclass_for_class_with_init`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonDataclassForClassWithInitRule;

const MIN_FIELDS: usize = 2;

impl Rule for PythonDataclassForClassWithInitRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.python_dataclass_for_class_with_init"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "class whose `__init__` only assigns to self — consider `@dataclass`"
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
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
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
    let lines: Vec<&str> = text.lines().collect();
    for idx in 0..lines.len() {
        let Some(class_indent) = parse_class_header(lines[idx]) else {
            continue;
        };
        if has_dataclass_decorator(&lines, idx) {
            continue;
        }
        if let Some(field_count) = class_has_pure_assign_init(&lines, idx, class_indent) {
            if field_count >= MIN_FIELDS {
                out.push(emit(path.clone(), idx + 1, lines[idx], field_count));
            }
        }
    }
}

/// Match `class <name>(...):` or `class <name>:`. Returns the indent
/// column of the class header, or `None` if not a class header.
fn parse_class_header(line: &str) -> Option<usize> {
    let indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    let trimmed = &line[indent..];
    if !trimmed.starts_with("class ") {
        return None;
    }
    if !trimmed.contains(':') {
        return None;
    }
    Some(indent)
}

/// Look at the line immediately above the class header. Skip blank
/// lines; any decorator line beginning with `@dataclass` or
/// `@dataclasses.dataclass` disqualifies the class.
fn has_dataclass_decorator(lines: &[&str], class_idx: usize) -> bool {
    let mut idx = class_idx;
    while idx > 0 {
        idx -= 1;
        let trimmed = lines[idx].trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.starts_with('@') {
            return false;
        }
        if trimmed.starts_with("@dataclass") || trimmed.starts_with("@dataclasses.dataclass") {
            return true;
        }
    }
    false
}

/// Walk the class body looking for a `__init__` whose body is purely
/// `self.<x> = <x>` lines. Returns the number of fields when matched,
/// `None` otherwise.
fn class_has_pure_assign_init(
    lines: &[&str],
    class_idx: usize,
    class_indent: usize,
) -> Option<usize> {
    let body_indent = class_indent + 4;
    let init_idx = find_init_def(lines, class_idx + 1, class_indent, body_indent)?;
    let init_body_indent = body_indent + 4;
    count_pure_assign_lines(lines, init_idx + 1, init_body_indent)
}

/// Walk the body lines of `__init__` and count pure `self.x = x`
/// statements until first dedent. Returns the count, or `None` if the
/// body contains any non-pure-assign line.
fn count_pure_assign_lines(lines: &[&str], start: usize, body_indent: usize) -> Option<usize> {
    let mut fields: usize = 0;
    for line in lines.iter().skip(start) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = leading_indent(line);
        if indent < body_indent {
            break;
        }
        if !line_is_pure_self_assign(line, body_indent) {
            return None;
        }
        fields += 1;
    }
    Some(fields)
}

/// Return the line index of the first `def __init__(self, ...):` whose
/// indent matches `body_indent`. Bail at first dedent below the class.
fn find_init_def(
    lines: &[&str],
    start: usize,
    class_indent: usize,
    body_indent: usize,
) -> Option<usize> {
    for (offset, line) in lines.iter().enumerate().skip(start) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = leading_indent(line);
        if indent <= class_indent {
            return None;
        }
        if indent != body_indent {
            continue;
        }
        let trimmed = &line[indent..];
        if trimmed.starts_with("def __init__(self") {
            return Some(offset);
        }
    }
    None
}

fn leading_indent(line: &str) -> usize {
    line.bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count()
}

/// Match `self.<x> = <x>` exactly — same identifier on both sides.
fn line_is_pure_self_assign(line: &str, expected_indent: usize) -> bool {
    let indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    if indent != expected_indent {
        return false;
    }
    let trimmed = &line[indent..];
    let Some(rest) = trimmed.strip_prefix("self.") else {
        return false;
    };
    let Some(eq_idx) = rest.find(" = ") else {
        return false;
    };
    let attr = rest[..eq_idx].trim();
    let value = rest[eq_idx + 3..].trim();
    is_simple_ident(attr) && attr == value
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.as_bytes()[0].is_ascii_digit()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, fields: usize) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.python_dataclass_for_class_with_init",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("class with {fields}-field plain `__init__` — consider `@dataclass`"),
        explanation: format!(
            "The `__init__` does nothing but assign each parameter to \
             `self.<same_name>`. Python 3.7's `@dataclass` decorator \
             generates exactly that constructor (plus `__repr__` and \
             `__eq__`) from class-level type annotations. {fields} \
             fields here: dropping the `__init__` removes \
             {body} lines of boilerplate and gains a free \
             `__repr__` — currently any debug print of an instance \
             returns `<__main__.Cls object at 0x...>` which is \
             nearly useless.",
            body = fields + 1
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add `from dataclasses import dataclass`, decorate the \
             class with `@dataclass`, and replace the `__init__` body \
             with class-level type annotations: \
             `name: str`, `age: int`, etc. Use `field(default=...)` \
             when parameters had defaults, and `frozen=True` if the \
             class is immutable."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
