//! [`Kernel`] — the orchestrator that wires every other crate together.
//!
//! Responsibilities, in order:
//!
//! 1. Hold a validated [`Config`] + a [`RuleRegistry`] + a fingerprint
//!    placeholder + a [`ScoreEngine`].
//! 2. On `run`, walk the repo (`walker::walk_repo`).
//! 3. In parallel via `rayon`, parse + lift every supported file.
//! 4. For every (file, batch) pair, run every rule via
//!    [`cc_rules::run_rule`] and accumulate findings.
//! 5. Compute a deterministic [`cc_score::HealthScore`].
//! 6. Emit findings to a caller-supplied [`FindingSink`].
//! 7. Return a [`KernelRunReport`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use camino::{Utf8Path, Utf8PathBuf};
use cc_config::Config;
use cc_cpg::CpgWriteBatch;
use cc_finding::{Finding, FindingSink};
use cc_frontend::{FileId, LanguageFrontend};
use cc_rules::{
    run_rule, FileBackedSourceTable, KernelMeta, ProjectFingerprint, RuleContext, RulePack,
    RuleRegistry,
};
use cc_rules_anti_fragility::BuiltinAntiFragilityPack;
use cc_rules_api::BuiltinApiPack;
use cc_rules_architecture::BuiltinArchitecturePack;
use cc_rules_bugs::BuiltinBugsPack;
use cc_rules_ci::BuiltinCiPack;
use cc_rules_completeness::BuiltinCompletenessPack;
use cc_rules_compliance::BuiltinCompliancePack;
use cc_rules_concurrency::BuiltinConcurrencyPack;
use cc_rules_conventions::BuiltinConventionsPack;
use cc_rules_database::BuiltinDatabasePack;
use cc_rules_deploy::BuiltinDeployPack;
use cc_rules_docs::BuiltinDocsPack;
use cc_rules_formatting::BuiltinFormattingPack;
use cc_rules_history::BuiltinHistoryPack;
use cc_rules_i18n_a11y::BuiltinI18nA11yPack;
use cc_rules_iac::BuiltinIacPack;
use cc_rules_memory::BuiltinMemoryPack;
use cc_rules_modernize::BuiltinModernizePack;
use cc_rules_observability::BuiltinObservabilityPack;
use cc_rules_ops::BuiltinOpsPack;
use cc_rules_perf::BuiltinPerfPack;
use cc_rules_secrets::BuiltinSecretsPack;
use cc_rules_slop::BuiltinSlopPack;
use cc_rules_supplychain::BuiltinSupplyChainPack;
use cc_rules_taint::BuiltinTaintPack;
use cc_rules_test_design::BuiltinTestDesignPack;
use cc_rules_tests::BuiltinTestsPack;
use cc_rules_tier0::BuiltinTier0Pack;
use cc_rules_time_math::BuiltinTimeMathPack;
use cc_rules_types::BuiltinTypesPack;
use cc_score::ScoreEngine;
use rayon::prelude::*;

use crate::error::{KernelError, KernelResult};
use crate::language::frontend_for_path;
use crate::report::{KernelRunReport, PerRuleTiming};
use crate::walker::walk_repo;

/// The orchestrator. Owns everything the run needs except the repo
/// itself (which is passed per-call so a single kernel can be reused
/// across watched roots).
pub struct Kernel {
    config: Config,
    registry: RuleRegistry,
    fingerprint: Arc<ProjectFingerprint>,
    score_engine: ScoreEngine,
}

impl Kernel {
    /// Build a kernel from a validated [`Config`].
    ///
    /// The registry starts empty — call [`Kernel::with_default_packs`] to
    /// register the built-in Tier-0 pack, or [`Kernel::with_pack`] to
    /// register a custom pack.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Result` to keep the constructor
    /// future-proof against config-derived validation.
    pub fn new(config: Config) -> KernelResult<Self> {
        Ok(Self {
            config,
            registry: RuleRegistry::new(),
            fingerprint: Arc::new(ProjectFingerprint::empty()),
            score_engine: ScoreEngine::standard(),
        })
    }

    /// Register a [`RulePack`] with this kernel's registry.
    ///
    /// # Errors
    ///
    /// Propagates [`KernelError::Registry`] when the pack collides with
    /// an existing pack id, contributes a duplicate rule id, or sits
    /// outside the kernel's API window.
    pub fn with_pack<P: RulePack>(&mut self, pack: &P) -> KernelResult<&mut Self> {
        self.registry.register_pack(pack)?;
        Ok(self)
    }

    /// Register every shipped built-in pack.
    ///
    /// Phase-1 ships [`BuiltinTier0Pack`] (16 forever rules); Phase-2
    /// adds [`BuiltinSlopPack`] (8 Family-1 slop & drift rules),
    /// [`BuiltinSecretsPack`] (16 Family-19 config + secret rules),
    /// [`BuiltinPerfPack`] (9 Family-2 static-performance rules), and
    /// [`BuiltinCompletenessPack`] (28 Family-25 structural-completeness
    /// rules); Phase-3 adds [`BuiltinBugsPack`] (7 Family-3 correctness
    /// rules), [`BuiltinConcurrencyPack`] (5 Family-5 concurrency
    /// rules), [`BuiltinTimeMathPack`] (5 Family-14 time + math
    /// rules), and [`BuiltinTaintPack`] (7 Family-4 taint / security
    /// flow rules); Phase-5 adds [`BuiltinDocsPack`] (5 Family-16
    /// documentation rules), [`BuiltinCompliancePack`], and
    /// [`BuiltinI18nA11yPack`] (5 Family-15 i18n + a11y rules);
    /// Phase-6 adds [`BuiltinModernizePack`] (10 Family-26 modernization
    /// / version-skew rules), [`BuiltinTestDesignPack`] (10 Family-28
    /// test-design + mutation-health rules), and
    /// [`BuiltinSupplyChainPack`] (10 Family-32 supply-chain attestation
    /// + dependency hygiene rules). Newer packs land here as they ship.
    ///
    /// # Errors
    ///
    /// See [`Kernel::with_pack`].
    pub fn with_default_packs(&mut self) -> KernelResult<&mut Self> {
        self.register_phase_1_packs()?;
        self.register_phase_2_packs()?;
        self.register_phase_3_packs()?;
        self.register_phase_4_packs()?;
        self.register_phase_5_packs()?;
        self.register_phase_6_packs()?;
        Ok(self)
    }

    /// Phase 1: the Tier-0 forever-rules pack.
    fn register_phase_1_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinTier0Pack)?;
        Ok(())
    }

    /// Phase 2: slop, secrets, perf, completeness.
    fn register_phase_2_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinSlopPack)?;
        self.registry.register_pack(&BuiltinSecretsPack)?;
        self.registry.register_pack(&BuiltinPerfPack)?;
        self.registry.register_pack(&BuiltinCompletenessPack)?;
        Ok(())
    }

    /// Phase 3: bugs, concurrency, time-math, taint, memory, types,
    /// architecture, layout conventions.
    fn register_phase_3_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinBugsPack)?;
        self.registry.register_pack(&BuiltinConcurrencyPack)?;
        self.registry.register_pack(&BuiltinTimeMathPack)?;
        self.registry.register_pack(&BuiltinTaintPack)?;
        self.registry.register_pack(&BuiltinMemoryPack)?;
        self.registry.register_pack(&BuiltinTypesPack)?;
        self.registry.register_pack(&BuiltinArchitecturePack)?;
        self.registry.register_pack(&BuiltinConventionsPack)?;
        Ok(())
    }

    /// Phase 4: tests, database, anti-fragility, observability, api,
    /// deploy, ops, ci, history.
    fn register_phase_4_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinTestsPack)?;
        self.registry.register_pack(&BuiltinDatabasePack)?;
        self.registry.register_pack(&BuiltinAntiFragilityPack)?;
        self.registry.register_pack(&BuiltinObservabilityPack)?;
        self.registry.register_pack(&BuiltinApiPack)?;
        self.registry.register_pack(&BuiltinDeployPack)?;
        self.registry.register_pack(&BuiltinOpsPack)?;
        self.registry.register_pack(&BuiltinCiPack)?;
        self.registry.register_pack(&BuiltinHistoryPack)?;
        Ok(())
    }

    /// Phase 5: docs, compliance, i18n + a11y.
    fn register_phase_5_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinDocsPack)?;
        self.registry.register_pack(&BuiltinCompliancePack)?;
        self.registry.register_pack(&BuiltinI18nA11yPack)?;
        Ok(())
    }

    /// Phase 6: modernization / version-skew, test design + mutation
    /// health, supply-chain attestation + dependency hygiene,
    /// formatting drift, IaC + cloud config.
    fn register_phase_6_packs(&mut self) -> KernelResult<()> {
        self.registry.register_pack(&BuiltinModernizePack)?;
        self.registry.register_pack(&BuiltinTestDesignPack)?;
        self.registry.register_pack(&BuiltinSupplyChainPack)?;
        self.registry.register_pack(&BuiltinFormattingPack)?;
        self.registry.register_pack(&BuiltinIacPack)?;
        Ok(())
    }

    /// Run the kernel against `root`, dropping findings on the floor.
    ///
    /// Equivalent to `run_with_sink` with a no-op sink.
    ///
    /// # Errors
    ///
    /// See [`Kernel::run_with_sink`].
    pub fn run(&self, root: &Utf8Path) -> KernelResult<KernelRunReport> {
        let mut sink = NoopSink;
        self.run_with_sink(root, &mut sink)
    }

    /// Run the kernel against `root`, emitting every finding through `sink`.
    ///
    /// # Errors
    ///
    /// - [`KernelError::GlobCompile`] when the walker cannot compile the
    ///   ignore globs.
    /// - [`KernelError::Sink`] when the supplied sink rejects a finding.
    pub fn run_with_sink(
        &self,
        root: &Utf8Path,
        sink: &mut dyn FindingSink,
    ) -> KernelResult<KernelRunReport> {
        let started_at = SystemTime::now();
        let monotonic = Instant::now();

        let walk = walk_repo(root, &self.config)?;
        let walked_total = walk.included.len() + walk.skipped as usize;

        let lifted = parallel_lift(root, &walk.included);
        let scanned = u32::try_from(lifted.len()).unwrap_or(u32::MAX);
        let unsupported_or_failed = walked_total
            .saturating_sub(lifted.len())
            .saturating_sub(walk.skipped as usize);
        let files_skipped = walk
            .skipped
            .saturating_add(u32::try_from(unsupported_or_failed).unwrap_or(u32::MAX));

        let RunRulesOutput {
            findings,
            per_rule_timing,
        } = self.run_rules(root, &lifted);

        for finding in &findings {
            sink.emit(finding.clone())
                .map_err(|source| KernelError::Sink {
                    context: "emit_finding",
                    source,
                })?;
        }

        let score = self.score_engine.score(&findings);
        let elapsed = monotonic.elapsed();

        Ok(KernelRunReport {
            root: root.to_path_buf(),
            started_at,
            elapsed,
            files_scanned: scanned,
            files_skipped,
            findings,
            score,
            per_rule_timing,
        })
    }

    /// Inner loop: for every (path, batch), run every rule once.
    fn run_rules(
        &self,
        root: &Utf8Path,
        lifted: &[(Utf8PathBuf, CpgWriteBatch)],
    ) -> RunRulesOutput {
        let source_table = FileBackedSourceTable::new(root.to_path_buf());
        let kernel_meta = KernelMeta::now();
        let effective = self.registry.apply_config(&self.config);

        let mut findings: Vec<Finding> = Vec::new();
        let mut per_rule_timing: PerRuleTiming = BTreeMap::new();

        for (_path, batch) in lifted {
            for eff in &effective {
                if !eff.enabled {
                    continue;
                }
                let ctx = RuleContext {
                    batch,
                    source: &source_table,
                    config: &eff.config,
                    project: &self.fingerprint,
                    kernel: &kernel_meta,
                };
                let rule_started = Instant::now();
                let mut produced = run_rule(eff.rule, eff.pack_id, &ctx);
                let elapsed = rule_started.elapsed();
                accumulate_timing(&mut per_rule_timing, eff.rule.rule_id(), elapsed);
                findings.append(&mut produced);
            }
        }

        RunRulesOutput {
            findings,
            per_rule_timing,
        }
    }
}

/// Output of [`Kernel::run_rules`] — extracted so the outer `run`
/// stays well under the 50-LOC line budget.
struct RunRulesOutput {
    findings: Vec<Finding>,
    per_rule_timing: PerRuleTiming,
}

fn accumulate_timing(map: &mut PerRuleTiming, rule_id: &'static str, delta: Duration) {
    map.entry(rule_id.to_owned())
        .and_modify(|d| *d = d.saturating_add(delta))
        .or_insert(delta);
}

/// Parse-and-lift every candidate path in parallel via rayon.
///
/// Files that fail to parse or lift are logged at `tracing::warn` and
/// dropped from the result; the kernel reports them as `files_skipped`
/// in the run report.
fn parallel_lift(root: &Utf8Path, paths: &[Utf8PathBuf]) -> Vec<(Utf8PathBuf, CpgWriteBatch)> {
    paths
        .par_iter()
        .enumerate()
        .filter_map(|(idx, rel)| lift_one(root, rel, idx))
        .collect()
}

/// Parse + lift a single file. Returns `None` on any non-fatal error.
fn lift_one(root: &Utf8Path, rel: &Utf8Path, idx: usize) -> Option<(Utf8PathBuf, CpgWriteBatch)> {
    let frontend: Box<dyn LanguageFrontend> = frontend_for_path(rel)?;
    let absolute = root.join(rel);
    let source = match std::fs::read_to_string(absolute.as_std_path()) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(
                target: "cc_kernel::runner",
                path = %rel,
                error_kind = ?err.kind(),
                "could not read source; skipping"
            );
            return None;
        }
    };
    let tree = match frontend.parse(&source) {
        Ok(t) => t,
        Err(err) => {
            tracing::warn!(
                target: "cc_kernel::runner",
                path = %rel,
                error = %err,
                "parse failed; skipping"
            );
            return None;
        }
    };
    let mut batch = CpgWriteBatch::new();
    let file_id = FileId::new(idx as u64 + 1);
    if let Err(err) = frontend.lift(&tree, &source, &mut batch, file_id) {
        tracing::warn!(
            target: "cc_kernel::runner",
            path = %rel,
            error = %err,
            "lift failed; skipping"
        );
        return None;
    }
    let patched = patch_file_path(batch, rel);
    Some((rel.to_path_buf(), patched))
}

/// Inject the `path` property onto every `File` node in the batch.
///
/// Phase-1 frontends populate File nodes with `language` / `file_id` /
/// `range` but do *not* know the repo-relative path — the kernel does.
/// Several Tier-0 rules (`R-FN-LEN`, `R-FILE-LEN`, ...) walk
/// `enclosing_file_path`, which reads the `"path"` string prop. Patching
/// it here is the kernel's responsibility per the integration contract.
///
/// The patch round-trips the batch through `serde_json` because
/// `CpgWriteBatch` does not expose mutable node access. The cost is a
/// per-file allocation of one JSON value; acceptable for Phase 1 and
/// folded into the `parallel_lift` fan-out so it parallelises with parse.
/// TODO: replace with a direct setter once `cc-cpg` exposes one.
fn patch_file_path(batch: CpgWriteBatch, rel: &Utf8Path) -> CpgWriteBatch {
    let mut value = match serde_json::to_value(&batch) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                target: "cc_kernel::runner",
                error = %err,
                "could not serialize batch for path patch; returning original"
            );
            return batch;
        }
    };
    if let Some(nodes) = value.get_mut("nodes").and_then(|v| v.as_array_mut()) {
        for node in nodes {
            inject_path_into_file(node, rel);
        }
    }
    serde_json::from_value(value).unwrap_or(batch)
}

/// If `node` is a `File`-kind JSON object, set its `path` prop.
fn inject_path_into_file(node: &mut serde_json::Value, rel: &Utf8Path) {
    let kind_is_file = node
        .get("kind")
        .and_then(|k| k.as_str())
        .is_some_and(|s| s == "File");
    if !kind_is_file {
        return;
    }
    let Some(props) = node.get_mut("props").and_then(|v| v.as_object_mut()) else {
        return;
    };
    let entry = serde_json::json!({ "String": rel.as_str() });
    props.insert("path".to_owned(), entry);
}

/// No-op sink used by [`Kernel::run`] — drops every finding,
/// returns an empty summary.
#[derive(Debug)]
struct NoopSink;

impl FindingSink for NoopSink {
    fn emit(&mut self, _finding: Finding) -> cc_finding::Result<()> {
        Ok(())
    }

    fn finish(self: Box<Self>) -> cc_finding::Result<cc_finding::Summary> {
        Ok(cc_finding::Summary::new())
    }
}
