//! `cc.modernize.numpy_legacy_random` — `numpy.random.rand(...)`,
//! `numpy.random.randn(...)`, `numpy.random.seed(...)`, etc. The
//! NumPy 2.0 modernization story replaces the legacy module-level
//! random API with `numpy.random.default_rng()` (a `Generator`
//! instance) so seed state is explicit and reproducibility is
//! per-experiment instead of process-global.
//!
//! Mirrors ruff `NPY002` (numpy-legacy-random).
//!
//! Phase-10 detector: scan every `.py` file once for the legacy
//! callees in `LEGACY_RANDOM_CALLEES`. Receiver may be `np.random`
//! or `numpy.random`; aliasing is allowed via the standard `as np`
//! convention (the canonical alias enforced by
//! `cc.modernize.banned_import_alias`).
//!
//! Severity: `Nit`. Confidence 0.9 — call shape is concrete; the only
//! false positive is a project that intentionally targets NumPy <1.17
//! (legacy-only).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.numpy_legacy_random`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NumpyLegacyRandomRule;

/// Receiver prefixes that anchor a NumPy random call.
const RANDOM_RECEIVERS: &[&str] = &["np.random.", "numpy.random."];

/// Methods whose legacy form should migrate to `default_rng()`.
const LEGACY_RANDOM_CALLEES: &[&str] = &[
    "rand",
    "randn",
    "randint",
    "random",
    "random_sample",
    "ranf",
    "sample",
    "choice",
    "bytes",
    "shuffle",
    "permutation",
    "seed",
    "uniform",
    "normal",
    "standard_normal",
    "beta",
    "binomial",
    "exponential",
    "gamma",
    "geometric",
    "lognormal",
    "poisson",
];

impl Rule for NumpyLegacyRandomRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.numpy_legacy_random"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "use `numpy.random.default_rng()` instead of legacy module-level random API"
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
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(method) = find_legacy_random_call(line) {
            out.push(emit(path.clone(), line_idx + 1, line, method));
        }
    }
}

fn find_legacy_random_call(line: &str) -> Option<&'static str> {
    for receiver in RANDOM_RECEIVERS {
        if let Some(method) = scan_after_receiver(line, receiver) {
            return Some(method);
        }
    }
    None
}

fn scan_after_receiver(line: &str, receiver: &str) -> Option<&'static str> {
    let mut start = 0usize;
    while let Some(found) = line[start..].find(receiver) {
        let abs = start + found;
        if is_token_continuation(line, abs) {
            start = abs + receiver.len();
            continue;
        }
        if let Some(method) = match_legacy_call(&line[abs + receiver.len()..]) {
            return Some(method);
        }
        start = abs + receiver.len();
    }
    None
}

fn is_token_continuation(line: &str, idx: usize) -> bool {
    if idx == 0 {
        return false;
    }
    let prev = line.as_bytes()[idx - 1];
    prev.is_ascii_alphanumeric() || prev == b'_'
}

fn match_legacy_call(after: &str) -> Option<&'static str> {
    for method in LEGACY_RANDOM_CALLEES {
        let needle = format!("{method}(");
        if after.starts_with(&needle) {
            return Some(method);
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, method: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.numpy_legacy_random",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`np.random.{method}(...)` uses the legacy NumPy random API"),
        explanation: format!(
            "`np.random.{method}(...)` reads / mutates a process-global \
             RandomState. NumPy 2.0 supersedes that with \
             `np.random.default_rng()` — a `Generator` instance whose \
             seed is explicit and per-experiment. Test reproducibility \
             is local to the call instead of dependent on import order, \
             and parallel workers stop colliding on the shared seed."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Allocate a generator once per experiment / function: \
             `rng = np.random.default_rng(seed)` then call \
             `rng.{method}(...)`. The new API mirrors the legacy method \
             names so the migration is mostly a rename + thread the \
             generator through. Mirrors ruff NPY002."
        )),
        snippet,
        weight: 1,
    })
}
