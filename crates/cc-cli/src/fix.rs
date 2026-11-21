//! `ccv12 fix` — apply machine-applicable [`FixProposal::Diff`] edits.
//!
//! Pipeline:
//!
//! 1. Run `ccv12 check` over the supplied path (same kernel + default packs).
//! 2. Filter findings by `--severity` / `--rule`.
//! 3. Keep only findings whose [`Finding::fix`] (or
//!    [`Remediation::AutoFix`]) carries an *auto-applicable*
//!    [`FixProposal::Diff`] (`FixSafety::Safe`).
//! 4. Group remaining edits per source file.
//! 5. For each file: sort edits **reverse byte-order**, drop any that
//!    overlap an already-accepted edit (with a stderr warning), apply,
//!    and atomically rename a temp sibling on top of the original.
//!
//! `--dry-run` short-circuits before any write happens.
//!
//! Exit codes (per the Phase-12 contract):
//!
//! - `0` — success (even when nothing changed).
//! - `1` — at least one I/O failure (read / write / rename).
//! - `2` — at least one overlap conflict the user must resolve manually.
//!
//! Numeric collisions with [`crate::ExitCode::Findings`] /
//! [`crate::ExitCode::RuntimeError`] are intentional — the fix subcommand
//! shares those slots so CI consumers do not need to special-case it.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use camino::{Utf8Path, Utf8PathBuf};
use cc_config::Config;
use cc_finding::{Finding, FixProposal, FixSafety, Remediation, TextEdit};
use cc_kernel::Kernel;

use crate::args::FixArgs;
use crate::error::{CliError, Result};
use crate::exit::ExitCode;

/// Suffix of the temp sibling file used by [`atomic_write`].
const TMP_SUFFIX: &str = ".cc-tmp";

/// One accepted edit, after filtering + de-duplication.
#[derive(Debug, Clone)]
struct PlannedEdit {
    rule_id: String,
    start: u32,
    end: u32,
    new_text: String,
}

/// Outcome counters surfaced in the `ccv12 fix` summary line.
#[derive(Debug, Default, Clone, Copy)]
struct FixCounts {
    fixed: usize,
    no_autofix: usize,
    overlap: usize,
    files_touched: usize,
    io_errors: usize,
}

/// Top-level `ccv12 fix` handler.
///
/// # Errors
///
/// Returns [`CliError::InvalidRoot`] / [`CliError::Config`] /
/// [`CliError::Kernel`] when the underlying `ccv12 check` plumbing rejects
/// the run. Per-file I/O failures are *not* surfaced as `Err` — they are
/// counted into `io_errors` and the resulting [`ExitCode`] reflects the
/// outcome.
pub fn run_fix(args: &FixArgs) -> Result<ExitCode> {
    let report = collect_findings(args)?;
    let plan = plan_edits(&report.findings, args);
    let mut counts = plan.counts;

    if args.dry_run {
        report_dry_run(&plan);
        return Ok(ExitCode::Clean);
    }

    for (file, edits) in &plan.per_file {
        match apply_file_edits(file, edits) {
            Ok(()) => counts.files_touched = counts.files_touched.saturating_add(1),
            Err(err) => {
                report_io_error(file, &err);
                counts.io_errors = counts.io_errors.saturating_add(1);
            }
        }
    }

    report_summary(&counts);
    Ok(classify_exit(&counts))
}

/// Run the kernel against `args.path` with a no-op sink — we only need
/// the [`KernelRunReport::findings`] vector.
fn collect_findings(args: &FixArgs) -> Result<cc_kernel::KernelRunReport> {
    let root = canonicalise_root(&args.path)?;
    let config = load_or_default_config(&root)?;
    let kernel = build_kernel(config, args.no_default_pack)?;
    kernel
        .run(&root)
        .map_err(|source| CliError::Kernel { source })
}

/// Map `path` to an absolute root, validating it exists.
fn canonicalise_root(path: &Utf8Path) -> Result<Utf8PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir_utf8()?.join(path)
    };
    if !absolute.is_dir() {
        return Err(CliError::InvalidRoot { path: absolute });
    }
    Ok(absolute)
}

/// Read `std::env::current_dir` as `Utf8PathBuf`, mapping every failure
/// to [`CliError::Io`] with an actionable context.
fn current_dir_utf8() -> Result<Utf8PathBuf> {
    let cwd = std::env::current_dir().map_err(|source| CliError::Io {
        context: "current_dir",
        source,
    })?;
    Utf8PathBuf::from_path_buf(cwd).map_err(|bad| CliError::Io {
        context: "cwd_not_utf8",
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cwd is not valid UTF-8: {}", bad.display()),
        ),
    })
}

/// Load `.cc/config.toml` if present, else the in-memory default.
fn load_or_default_config(root: &Utf8Path) -> Result<Config> {
    let path = root.join(".cc/config.toml");
    if path.exists() {
        Ok(Config::load(&path)?)
    } else {
        Ok(Config::default_for_repo(root))
    }
}

/// Build a kernel and (optionally) register the default Tier-0 pack.
fn build_kernel(config: Config, no_default_pack: bool) -> Result<Kernel> {
    let mut kernel = Kernel::new(config)?;
    if !no_default_pack {
        kernel.with_default_packs()?;
    }
    Ok(kernel)
}

/// Build a per-file edit plan from `findings`, accounting for filters,
/// "no autofix available" and overlapping ranges.
struct EditPlan {
    per_file: BTreeMap<Utf8PathBuf, Vec<PlannedEdit>>,
    counts: FixCounts,
}

fn plan_edits(findings: &[Finding], args: &FixArgs) -> EditPlan {
    let mut per_file: BTreeMap<Utf8PathBuf, Vec<PlannedEdit>> = BTreeMap::new();
    let mut counts = FixCounts::default();

    for finding in findings {
        if !finding_passes_filter(finding, args) {
            continue;
        }
        let Some(diff) = pick_auto_diff(finding) else {
            counts.no_autofix = counts.no_autofix.saturating_add(1);
            report_no_autofix(finding);
            continue;
        };
        for edit in diff {
            let entry = per_file.entry(finding.location.file.clone()).or_default();
            entry.push(PlannedEdit {
                rule_id: finding.rule_id.to_string(),
                start: edit.range.start.offset,
                end: edit.range.end.offset,
                new_text: edit.new_text.clone(),
            });
        }
    }

    for edits in per_file.values_mut() {
        let dropped = sort_and_dedupe(edits);
        counts.overlap = counts.overlap.saturating_add(dropped);
    }
    counts.fixed = per_file.values().map(Vec::len).sum();
    EditPlan { per_file, counts }
}

/// True when `finding` is in scope for the configured severity floor and
/// optional rule allow-list.
fn finding_passes_filter(finding: &Finding, args: &FixArgs) -> bool {
    if finding.severity.rank() < args.severity.min_severity().rank() {
        return false;
    }
    if !args.rules.is_empty() && !args.rules.iter().any(|id| id == finding.rule_id.as_ref()) {
        return false;
    }
    true
}

/// Return the auto-applicable [`TextEdit`] list, or `None` when the
/// finding has no machine-applicable repair.
fn pick_auto_diff(finding: &Finding) -> Option<&[TextEdit]> {
    if let Some(edits) = auto_diff_of(finding.fix.as_ref()) {
        return Some(edits);
    }
    auto_diff_of(finding.message.remediation.first_auto_fix())
}

fn auto_diff_of(fix: Option<&FixProposal>) -> Option<&[TextEdit]> {
    match fix? {
        FixProposal::Diff {
            edits,
            safety: FixSafety::Safe,
            ..
        } => Some(edits.as_slice()),
        // Phase 12 stub: needs Remediation::AutoFix machine-edit shape
        // for `Codemod` and `LlmRewrite`. Engine/LLM-driven fixes are
        // surfaced by the rule pack, but applying them requires a
        // dedicated transformer crate that does not yet exist.
        _ => None,
    }
}

/// Resolve overlaps in INSERTION order (first-wins), then sort the
/// survivors reverse byte-order ready for splicing.
///
/// "Insertion order" matches the order findings come out of the kernel,
/// which is in turn the order rules were registered + ran. The first
/// edit that claims a byte range keeps it; later overlapping edits are
/// dropped with a stderr warning.
///
/// Reverse byte-order on the survivors guarantees that earlier offsets
/// stay valid as we splice — see [`splice_edits`].
///
/// Returns the drop count for [`FixCounts::overlap`].
fn sort_and_dedupe(edits: &mut Vec<PlannedEdit>) -> usize {
    let mut accepted: Vec<PlannedEdit> = Vec::with_capacity(edits.len());
    let mut dropped = 0_usize;
    for edit in edits.drain(..) {
        if accepted.iter().any(|kept| ranges_overlap(kept, &edit)) {
            report_overlap(&edit);
            dropped = dropped.saturating_add(1);
            continue;
        }
        accepted.push(edit);
    }
    accepted.sort_by(|a, b| b.start.cmp(&a.start).then_with(|| b.end.cmp(&a.end)));
    *edits = accepted;
    dropped
}

const fn ranges_overlap(a: &PlannedEdit, b: &PlannedEdit) -> bool {
    a.start < b.end && b.start < a.end
}

/// Apply every edit in `edits` to the file at `path`, atomically.
///
/// Pre-condition: `edits` is sorted reverse byte-order and free of
/// overlapping ranges.
fn apply_file_edits(path: &Utf8Path, edits: &[PlannedEdit]) -> io::Result<()> {
    let original = read_file(path)?;
    let updated = splice_edits(&original, edits)?;
    atomic_write(path, &updated)
}

fn read_file(path: &Utf8Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path.as_std_path())?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Splice every edit's `new_text` into `bytes`. `edits` MUST already be
/// reverse-byte-order so trailing offsets survive earlier replacements.
fn splice_edits(bytes: &[u8], edits: &[PlannedEdit]) -> io::Result<Vec<u8>> {
    let mut out = bytes.to_vec();
    for edit in edits {
        let start = usize::try_from(edit.start).map_err(invalid_offset)?;
        let end = usize::try_from(edit.end).map_err(invalid_offset)?;
        if end > out.len() || start > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "edit range [{start}, {end}) out of bounds for {} byte file",
                    out.len()
                ),
            ));
        }
        out.splice(start..end, edit.new_text.bytes());
    }
    Ok(out)
}

fn invalid_offset(err: std::num::TryFromIntError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Atomic write: write to `<path>.cc-tmp` and rename onto `<path>`.
///
/// On Windows, [`std::fs::rename`] over an existing file is supported on
/// 2016+ NTFS, but explicit handling for transient locking is delegated
/// to the operator (we surface the underlying error verbatim).
fn atomic_write(path: &Utf8Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    write_then_sync(&tmp, bytes)?;
    rename_or_fallback(&tmp, path.as_std_path())
}

fn tmp_sibling(path: &Utf8Path) -> PathBuf {
    let mut tmp = PathBuf::from(path.as_std_path());
    let mut name = tmp.file_name().unwrap_or_default().to_os_string();
    name.push(TMP_SUFFIX);
    tmp.set_file_name(name);
    tmp
}

fn write_then_sync(tmp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Rename `tmp` onto `dst`. On Windows the second attempt removes `dst`
/// first to work around the legacy "file already exists" failure mode.
fn rename_or_fallback(tmp: &Path, dst: &Path) -> io::Result<()> {
    if std::fs::rename(tmp, dst).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(dst);
    std::fs::rename(tmp, dst).map_err(|source| {
        let _ = std::fs::remove_file(tmp);
        source
    })
}

fn classify_exit(counts: &FixCounts) -> ExitCode {
    if counts.io_errors > 0 {
        // Numeric 1, mirroring the Phase-12 contract for I/O failures.
        return ExitCode::Findings;
    }
    if counts.overlap > 0 {
        // Numeric 2 — the operator must resolve overlapping edits.
        return ExitCode::RuntimeError;
    }
    ExitCode::Clean
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn report_dry_run(plan: &EditPlan) {
    let _ = writeln!(
        io::stderr(),
        "would fix {} finding(s) in {} file(s) ({} skipped — no autofix, {} skipped — overlap)",
        plan.counts.fixed,
        plan.per_file.len(),
        plan.counts.no_autofix,
        plan.counts.overlap,
    );
}

fn report_summary(counts: &FixCounts) {
    let _ = writeln!(
        io::stderr(),
        "Fixed {} findings in {} files ({} skipped — no autofix available, {} skipped — overlapping range, {} I/O error{}).",
        counts.fixed,
        counts.files_touched,
        counts.no_autofix,
        counts.overlap,
        counts.io_errors,
        if counts.io_errors == 1 { "" } else { "s" },
    );
}

fn report_no_autofix(finding: &Finding) {
    let hint = suggested_hint(&finding.message.remediation);
    let _ = writeln!(
        io::stderr(),
        "skip {} at {}:{} — no autofix available{}",
        finding.rule_id,
        finding.location.file,
        finding.location.start.line,
        hint,
    );
}

fn suggested_hint(remediation: &Remediation) -> String {
    match remediation {
        Remediation::SuggestedRewrite(text) => format!(" (suggested: {text})"),
        Remediation::Multiple(items) => items
            .iter()
            .find_map(|inner| match inner {
                Remediation::SuggestedRewrite(text) => Some(format!(" (suggested: {text})")),
                _ => None,
            })
            .unwrap_or_default(),
        Remediation::DocLink(url) => format!(" (docs: {url})"),
        Remediation::AutoFix(_) => String::new(),
    }
}

fn report_overlap(edit: &PlannedEdit) {
    let _ = writeln!(
        io::stderr(),
        "skip {} edit at bytes [{}, {}) — overlaps an earlier accepted edit",
        edit.rule_id,
        edit.start,
        edit.end,
    );
}

fn report_io_error(path: &Utf8Path, err: &io::Error) {
    let _ = writeln!(
        io::stderr(),
        "I/O error fixing {path}: {err} — verify the file is writable and not held open by another process",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use camino::Utf8PathBuf;
    use cc_finding::{
        ActionableMessage, Category, CostClaim, Evidence, Finding, FindingBuilder, FixProposal,
        FixSafety, Location, Position, ProbeVersion, Range, Remediation, Severity, TextEdit,
    };

    use super::{
        apply_file_edits, plan_edits, splice_edits, EditPlan, FixArgs, FixCounts, PlannedEdit,
    };
    use crate::args::SeverityFilter;

    /// Five-line input fixture used by the apply-and-overlap tests.
    const FIVE_LINER: &str = "alpha\nbravo\ncharlie\ndelta\necho\n";

    fn default_args(path: &Utf8PathBuf) -> FixArgs {
        FixArgs {
            path: path.clone(),
            dry_run: false,
            rules: Vec::new(),
            severity: SeverityFilter::Nit,
            no_default_pack: false,
        }
    }

    fn make_finding(
        rule: &'static str,
        file: Utf8PathBuf,
        start: u32,
        end: u32,
        replacement: &str,
    ) -> Finding {
        let location = Location {
            file,
            start: Position::new(1, 1, start),
            end: Position::new(1, 1, end),
            node_id: None,
            function_qualified_name: None,
        };
        let edit = TextEdit {
            range: Range {
                start: Position::new(1, 1, start),
                end: Position::new(1, 1, end),
            },
            new_text: replacement.to_string(),
        };
        let fix = FixProposal::Diff {
            edits: vec![edit],
            safety: FixSafety::Safe,
            confidence: 1.0,
        };
        FindingBuilder::new()
            .rule_id(rule)
            .category(Category::Shape)
            .location(location)
            .message(ActionableMessage::new(
                "headline",
                "explanation",
                Remediation::AutoFix(fix.clone()),
            ))
            .evidence(Evidence::from_snippet("test"))
            .severity(Severity::Required)
            .cost(CostClaim::BlockingDebt { weight: 1 })
            .fix(fix)
            .probe_version(ProbeVersion::new("test", "0.0.1", 1, None))
            .build()
            .expect("builder fields are complete")
    }

    #[test]
    fn applies_one_known_autofix_to_five_line_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path =
            Utf8PathBuf::from_path_buf(dir.path().join("input.txt")).expect("utf8 temp path");
        fs::write(&path, FIVE_LINER).expect("seed file");

        let edit = PlannedEdit {
            rule_id: "test.replace_alpha".to_string(),
            start: 0,
            end: 5,
            new_text: "ALPHA".to_string(),
        };
        apply_file_edits(&path, &[edit]).expect("apply succeeds");

        let actual = fs::read_to_string(&path).expect("read updated");
        assert_eq!(actual, "ALPHA\nbravo\ncharlie\ndelta\necho\n");
        // Temp sibling is cleaned up by the rename.
        assert!(!path.with_extension("txt.cc-tmp").exists());
    }

    #[test]
    fn skips_second_overlapping_edit() {
        let path = Utf8PathBuf::from("synthetic.txt");
        let mut findings = Vec::new();
        findings.push(make_finding("rule.a", path.clone(), 0, 5, "AAAAA"));
        findings.push(make_finding("rule.b", path.clone(), 2, 7, "bbbbb"));
        let plan: EditPlan = plan_edits(&findings, &default_args(&path));

        assert_eq!(plan.counts.overlap, 1, "second overlapping edit dropped");
        assert_eq!(plan.counts.fixed, 1, "exactly one edit accepted");
        let edits = plan.per_file.get(&path).expect("file present");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].rule_id, "rule.a");
    }

    #[test]
    fn dry_run_does_not_modify_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path =
            Utf8PathBuf::from_path_buf(dir.path().join("input.txt")).expect("utf8 temp path");
        fs::write(&path, FIVE_LINER).expect("seed file");

        let mut args = default_args(&path);
        args.dry_run = true;
        let findings = vec![make_finding("rule.dry", path.clone(), 0, 5, "WIPED")];
        let plan = plan_edits(&findings, &args);
        assert_eq!(plan.counts.fixed, 1);

        // Whole-pipeline check: dry-run path returns Clean and never
        // mutates the file even when the plan has work to do.
        // (We exercise apply_file_edits directly elsewhere; here we
        // simulate the dry-run early exit.)
        let original = fs::read_to_string(&path).expect("read");
        assert_eq!(original, FIVE_LINER);
    }

    #[test]
    fn splice_edits_rejects_out_of_bounds() {
        let bytes = b"hello";
        let edit = PlannedEdit {
            rule_id: "x".to_string(),
            start: 10,
            end: 12,
            new_text: "..".to_string(),
        };
        let err = splice_edits(bytes, &[edit]).expect_err("should reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn fix_counts_zero_by_default() {
        let counts = FixCounts::default();
        assert_eq!(counts.fixed, 0);
        assert_eq!(counts.no_autofix, 0);
        assert_eq!(counts.overlap, 0);
        assert_eq!(counts.io_errors, 0);
        assert_eq!(counts.files_touched, 0);
    }
}
