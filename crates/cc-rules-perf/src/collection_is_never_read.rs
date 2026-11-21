//! `cc.perf.collection_is_never_read` — local `Vec<T>` / `HashMap<K,V>` /
//! `HashSet<T>` declared, mutated, but never observed.
//!
//! Canonical bug:
//! ```text
//! fn audit() {
//!     let mut log: Vec<Event> = Vec::new();
//!     for ev in stream() {
//!         log.push(ev);          // grows
//!     }
//!     // function returns; `log` never iterated, indexed, borrowed.
//! }
//! ```
//! The collection allocates, reallocates on growth, and then drops on
//! function exit without anyone reading a single element. Either the
//! caller forgot a `return log` / `&log` or the loop body should drop
//! the collection entirely.
//!
//! OSS source: clippy `collection_is_never_read`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files. For each
//! `let mut <name>: <Coll>... = ...;` declaration of a known
//! collection, scan the rest of the same `fn` body for a *read* of
//! `<name>` — any of `<name>.iter`, `<name>.len`, `<name>.is_empty`,
//! `<name>[`, `for ... in &<name>`, `for ... in <name>`, `&<name>`,
//! `<name>.contains`, `<name>.get`, `return <name>`, or a function
//! call that takes `<name>`. Flag when none are found yet at least
//! one *write* (push / insert / append / extend) occurred. Skip test
//! files and rule-pack source.
//!
//! Severity `Required`, confidence 0.85.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    apply_braces, build_finding, is_rust_test_path, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 probe R-COLLECTION-IS-NEVER-READ.
#[derive(Debug, Default, Clone, Copy)]
pub struct CollectionIsNeverReadRule;

const COLLECTION_TYPES: &[&str] = &[
    "Vec<",
    "VecDeque<",
    "HashMap<",
    "HashSet<",
    "BTreeMap<",
    "BTreeSet<",
    "Vec ",
    "HashMap ",
    "HashSet ",
];

const WRITE_METHODS: &[&str] = &[
    ".push(",
    ".push_back(",
    ".push_front(",
    ".extend(",
    ".append(",
    ".put(",
    ".reserve(",
];

const READ_METHODS: &[&str] = &[
    ".iter(",
    ".iter_mut(",
    ".into_iter(",
    ".into_values(",
    ".into_keys(",
    ".len(",
    ".is_empty(",
    ".contains(",
    ".contains_key(",
    ".get(",
    ".get_mut(",
    ".values(",
    ".values_mut(",
    ".keys(",
    ".drain(",
    ".as_slice(",
    ".as_mut_slice(",
    ".pop(",
    ".pop_back(",
    ".pop_front(",
    ".remove(",
    ".first(",
    ".last(",
    ".clone(",
    ".clear(",
    ".retain(",
    ".sort(",
    ".sort_by(",
    ".sort_unstable(",
    // `.insert` returns Option<V> / bool — usually consumed as read.
    ".insert(",
];

impl Rule for CollectionIsNeverReadRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.collection_is_never_read"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "local collection is mutated but never observed"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
                continue;
            }
            if is_rust_test_path(&path) || looks_like_rule_pack_source(&path) {
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
    for fn_range in collect_rust_fn_ranges(&lines) {
        scan_fn_body(&lines, fn_range, path, out);
    }
}

fn scan_fn_body(
    lines: &[&str],
    fn_range: (usize, usize),
    path: &Utf8PathBuf,
    out: &mut Vec<Finding>,
) {
    let (start, end) = fn_range;
    let body = &lines[start..end];
    let tail = trailing_expr(body);
    for (rel_idx, line) in body.iter().enumerate() {
        let Some((name, coll_label)) = detect_collection_decl(line) else {
            continue;
        };
        let after = &body[rel_idx + 1..];
        if !body_writes_to(after, &name) {
            continue;
        }
        if body_reads(after, &name) {
            continue;
        }
        if tail.as_deref() == Some(name.as_str()) {
            continue; // returned implicitly via tail expression
        }
        out.push(emit(
            path.clone(),
            start + rel_idx + 1,
            line,
            &name,
            coll_label,
        ));
    }
}

/// Best-effort: the body's tail expression is the last non-blank,
/// non-comment, non-`}` line trimmed of any trailing comma. Used to
/// detect implicit-return shapes like `fn build() -> Vec<T> { … out }`.
fn trailing_expr(body: &[&str]) -> Option<String> {
    for line in body.iter().rev() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t == "}" || t.starts_with('#') {
            continue;
        }
        let bare = t.trim_end_matches(',').trim_end_matches('}').trim();
        if bare.is_empty() {
            continue;
        }
        return Some(bare.to_owned());
    }
    None
}

/// Returns `(binding_name, collection_label)` when `line` is
/// `let mut <name>[: <Coll<...>>] = ...;`.
fn detect_collection_decl(line: &str) -> Option<(String, &'static str)> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("let mut ")?;
    let eq_idx = rest.find('=')?;
    let lhs = rest[..eq_idx].trim();
    let rhs = rest[eq_idx + 1..].trim_start();
    let (name, ty_decl) = split_lhs(lhs);
    if name.is_empty() {
        return None;
    }
    let label = match infer_collection_label(ty_decl, rhs) {
        Some(l) => l,
        None => return None,
    };
    Some((name.to_owned(), label))
}

fn split_lhs(lhs: &str) -> (&str, Option<&str>) {
    if let Some(colon) = lhs.find(':') {
        let name = lhs[..colon].trim();
        let ty = lhs[colon + 1..].trim();
        (name, Some(ty))
    } else {
        (lhs.trim(), None)
    }
}

fn infer_collection_label(ty_decl: Option<&str>, rhs: &str) -> Option<&'static str> {
    if let Some(ty) = ty_decl {
        for needle in COLLECTION_TYPES {
            if ty.starts_with(needle) {
                return Some(label_for(needle));
            }
        }
    }
    for ctor in COLLECTION_CTORS {
        if rhs.starts_with(ctor.0) {
            return Some(ctor.1);
        }
    }
    None
}

const COLLECTION_CTORS: &[(&str, &'static str)] = &[
    ("Vec::new(", "Vec"),
    ("Vec::with_capacity(", "Vec"),
    ("vec![", "Vec"),
    ("HashMap::new(", "HashMap"),
    ("HashMap::with_capacity(", "HashMap"),
    ("HashSet::new(", "HashSet"),
    ("HashSet::with_capacity(", "HashSet"),
    ("BTreeMap::new(", "BTreeMap"),
    ("BTreeSet::new(", "BTreeSet"),
    ("VecDeque::new(", "VecDeque"),
    ("VecDeque::with_capacity(", "VecDeque"),
];

fn label_for(needle: &str) -> &'static str {
    let stripped = needle.trim_end_matches('<').trim_end_matches(' ');
    match stripped {
        "Vec" => "Vec",
        "VecDeque" => "VecDeque",
        "HashMap" => "HashMap",
        "HashSet" => "HashSet",
        "BTreeMap" => "BTreeMap",
        "BTreeSet" => "BTreeSet",
        _ => "collection",
    }
}

fn body_writes_to(after: &[&str], name: &str) -> bool {
    after.iter().any(|line| {
        WRITE_METHODS
            .iter()
            .any(|m| line.contains(&format!("{name}{m}")))
    })
}

fn body_reads(after: &[&str], name: &str) -> bool {
    after.iter().any(|line| line_reads(line, name))
}

fn line_reads(line: &str, name: &str) -> bool {
    if READ_METHODS
        .iter()
        .any(|n| line.contains(&format!("{name}{n}")))
    {
        return true;
    }
    let bare_patterns = [
        format!("&{name}"),
        format!("&mut {name}"),
        format!("{name}["),
        format!("in {name}"),
        format!("in &{name}"),
        format!("return {name}"),
        format!("Ok({name})"),
        format!("Some({name})"),
    ];
    if bare_patterns.iter().any(|p| line.contains(p.as_str())) {
        return true;
    }
    if struct_init_shorthand(line, name) {
        return true;
    }
    passed_to_call(line, name)
}

/// True iff the line uses `<name>` as a struct-init field shorthand
/// or as a key in `key: <name>` — both forms read the binding.
fn struct_init_shorthand(line: &str, name: &str) -> bool {
    let trimmed = line.trim();
    let stripped = trimmed.trim_end_matches(',');
    if stripped == name {
        return true;
    }
    line.contains(&format!(": {name},")) || line.contains(&format!(": {name} "))
}

fn passed_to_call(line: &str, name: &str) -> bool {
    for pat in [
        format!("({name})"),
        format!("({name},"),
        format!(", {name})"),
        format!(", {name},"),
    ] {
        if line.contains(&pat) {
            return true;
        }
    }
    false
}

/// Collect `[start, end)` line index ranges for every `fn ...` in
/// `lines`, using brace-balance to find the body's matching `}`.
fn collect_rust_fn_ranges(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut start: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let header = trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("pub async fn ");
        if start.is_none() && header && line.contains('{') {
            start = Some(idx);
            depth = apply_braces(0, line);
            continue;
        }
        if let Some(s) = start {
            depth = apply_braces(depth, line);
            if depth <= 0 {
                out.push((s, idx + 1));
                start = None;
                depth = 0;
            }
        }
    }
    out
}

fn emit(
    path: Utf8PathBuf,
    line_no: usize,
    line: &str,
    name: &str,
    coll_label: &'static str,
) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.collection_is_never_read",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name}: {coll_label}` is filled but never observed"),
        explanation: format!(
            "`{name}` is constructed, written to, then dropped on \
             function exit without a single element being read, \
             iterated, indexed, or borrowed. Either the function is \
             missing a `return {name}` / `&{name}`, or the loop \
             body that fills it is dead code."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Either return / borrow `{name}` so a caller can use \
                 the contents, or remove the declaration and the \
                 writes. If the side-effects of the writes are what \
                 matters, document that explicitly so the next reader \
                 doesn't delete them."
        )),
        snippet,
        weight: 3,
    })
}
