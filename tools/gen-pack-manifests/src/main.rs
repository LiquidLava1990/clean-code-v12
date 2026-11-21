//! `gen-pack-manifests` — emit one OCI artifact manifest per built-in
//! rule pack registered by `cc-kernel::Kernel::with_default_packs`.
//!
//! The output JSON is the Clean-Code-V12 distribution manifest that
//! `oras push` consumes when shipping a rule pack to ghcr.io. Schema is
//! modeled after `CodeQL`'s `qlpack` distribution format, simplified for
//! the cc-rules `RulePack` trait.
//!
//! Invocation:
//!
//! ```text
//! cargo run -p gen-pack-manifests -- --out packs
//! ```
//!
//! Re-running the binary regenerates every `packs/<pack-id>.oci.json`
//! deterministically; commit the output.
//!
//! # Determinism
//!
//! Pack iteration order is fixed (matches `with_default_packs` phase
//! order) and per-pack rule order matches the pack's own `rules()`
//! slice, so `cargo run -p gen-pack-manifests` is reproducible.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fs;
use std::process::ExitCode;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use cc_rules::{RulePack, KERNEL_API_VERSION};
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
use serde::Serialize;

/// Stable media type identifying a Clean-Code-V12 rule-pack manifest
/// stored as an OCI artifact.
const MEDIA_TYPE: &str = "application/vnd.cleancode.v12.rulepack.v1+json";

/// OCI registry under which the built-in packs publish.
const REGISTRY_BASE: &str = "ghcr.io/liquidlava1990";

/// Source language declared on every built-in pack manifest. The
/// kernel itself is polyglot, so the manifest enumerates all four
/// shipped front-ends rather than hard-coding one.
const BUILTIN_LANGUAGES: &[&str] = &["python", "typescript", "go", "rust"];

#[derive(Debug, Serialize)]
struct OciManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: &'static str,
    name: String,
    version: String,
    #[serde(rename = "kernel-api")]
    kernel_api: KernelApiWindow,
    rules: Vec<String>,
    sources: Vec<Source>,
}

#[derive(Debug, Serialize)]
struct KernelApiWindow {
    min: u32,
    /// Explicitly emitted as `null` when the pack is open-ended.
    /// Downstream tooling distinguishes "no upper bound" from "field
    /// missing" so the field is always present.
    max: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Source {
    language: &'static str,
    url: String,
}

fn parse_args() -> Utf8PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" | "-o" => {
                if let Some(value) = args.next() {
                    return Utf8PathBuf::from(value);
                }
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {}
        }
    }
    Utf8PathBuf::from("packs")
}

fn print_usage() {
    println!(
        "gen-pack-manifests — emit one OCI artifact manifest per built-in rule pack.\n\
         \n\
         USAGE:\n\
         \tgen-pack-manifests [--out <DIR>]\n\
         \n\
         FLAGS:\n\
         \t--out, -o   Directory to write <pack-id>.oci.json into. Default: ./packs\n\
         \t--help, -h  Print this message."
    );
}

fn render(pack: &dyn RulePack) -> OciManifest {
    let pack_id = pack.pack_id().to_string();
    let url = format!("{REGISTRY_BASE}/{pack_id}:{}", pack.pack_semver());
    let sources = BUILTIN_LANGUAGES
        .iter()
        .map(|lang| Source {
            language: lang,
            url: url.clone(),
        })
        .collect();
    OciManifest {
        schema_version: 2,
        media_type: MEDIA_TYPE,
        name: pack_id,
        version: pack.pack_semver().to_string(),
        kernel_api: KernelApiWindow {
            min: pack.kernel_api_min(),
            max: pack.kernel_api_max(),
        },
        rules: pack
            .rules()
            .iter()
            .map(|rule| rule.rule_id().to_string())
            .collect(),
        sources,
    }
}

fn write_manifest(out_dir: &camino::Utf8Path, pack: &dyn RulePack) -> Result<()> {
    let manifest = render(pack);
    let path = out_dir.join(format!("{}.oci.json", pack.pack_id()));
    let mut json = serde_json::to_string_pretty(&manifest)
        .with_context(|| format!("serialise manifest for pack {}", pack.pack_id()))?;
    json.push('\n');
    fs::write(&path, json).with_context(|| format!("write manifest to {path}"))?;
    println!(
        "wrote {path} ({} rules, kernel-api min={})",
        manifest.rules.len(),
        manifest.kernel_api.min
    );
    Ok(())
}

// Static instances of every built-in pack. One per pack — the kernel
// embeds them as zero-sized types, so the cost is negligible. Order
// mirrors `Kernel::with_default_packs` phase 1..5.
static TIER0: BuiltinTier0Pack = BuiltinTier0Pack;
static SLOP: BuiltinSlopPack = BuiltinSlopPack;
static SECRETS: BuiltinSecretsPack = BuiltinSecretsPack;
static PERF: BuiltinPerfPack = BuiltinPerfPack;
static COMPLETENESS: BuiltinCompletenessPack = BuiltinCompletenessPack;
static BUGS: BuiltinBugsPack = BuiltinBugsPack;
static CONCURRENCY: BuiltinConcurrencyPack = BuiltinConcurrencyPack;
static TIME_MATH: BuiltinTimeMathPack = BuiltinTimeMathPack;
static TAINT: BuiltinTaintPack = BuiltinTaintPack;
static MEMORY: BuiltinMemoryPack = BuiltinMemoryPack;
static TYPES: BuiltinTypesPack = BuiltinTypesPack;
static ARCH: BuiltinArchitecturePack = BuiltinArchitecturePack;
static CONVENTIONS: BuiltinConventionsPack = BuiltinConventionsPack;
static TESTS: BuiltinTestsPack = BuiltinTestsPack;
static DATABASE: BuiltinDatabasePack = BuiltinDatabasePack;
static ANTI_FRAGILITY: BuiltinAntiFragilityPack = BuiltinAntiFragilityPack;
static OBSERVABILITY: BuiltinObservabilityPack = BuiltinObservabilityPack;
static API: BuiltinApiPack = BuiltinApiPack;
static DEPLOY: BuiltinDeployPack = BuiltinDeployPack;
static OPS: BuiltinOpsPack = BuiltinOpsPack;
static CI: BuiltinCiPack = BuiltinCiPack;
static HISTORY: BuiltinHistoryPack = BuiltinHistoryPack;
static DOCS: BuiltinDocsPack = BuiltinDocsPack;
static COMPLIANCE: BuiltinCompliancePack = BuiltinCompliancePack;
static I18N_A11Y: BuiltinI18nA11yPack = BuiltinI18nA11yPack;
static MODERNIZE: BuiltinModernizePack = BuiltinModernizePack;
static TEST_DESIGN: BuiltinTestDesignPack = BuiltinTestDesignPack;
static SUPPLY_CHAIN: BuiltinSupplyChainPack = BuiltinSupplyChainPack;
static FORMATTING: BuiltinFormattingPack = BuiltinFormattingPack;
static IAC: BuiltinIacPack = BuiltinIacPack;

fn all_packs() -> Vec<&'static dyn RulePack> {
    vec![
        &TIER0,
        &SLOP,
        &SECRETS,
        &PERF,
        &COMPLETENESS,
        &BUGS,
        &CONCURRENCY,
        &TIME_MATH,
        &TAINT,
        &MEMORY,
        &TYPES,
        &ARCH,
        &CONVENTIONS,
        &TESTS,
        &DATABASE,
        &ANTI_FRAGILITY,
        &OBSERVABILITY,
        &API,
        &DEPLOY,
        &OPS,
        &CI,
        &HISTORY,
        &DOCS,
        &COMPLIANCE,
        &I18N_A11Y,
        &MODERNIZE,
        &TEST_DESIGN,
        &SUPPLY_CHAIN,
        &FORMATTING,
        &IAC,
    ]
}

fn run(out_dir: &camino::Utf8Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create output directory {out_dir}"))?;
    let packs = all_packs();
    let total_rules: usize = packs.iter().map(|pack| pack.rules().len()).sum();
    for pack in &packs {
        write_manifest(out_dir, *pack)?;
    }
    println!(
        "\ngenerated {} manifest(s) covering {} rules; kernel-api={}",
        packs.len(),
        total_rules,
        KERNEL_API_VERSION
    );
    Ok(())
}

fn main() -> ExitCode {
    let out_dir = parse_args();
    match run(&out_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("gen-pack-manifests: {err:#}");
            ExitCode::FAILURE
        }
    }
}
