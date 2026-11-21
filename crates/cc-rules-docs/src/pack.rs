//! [`BuiltinDocsPack`] — registers the eight Family-16 probes
//! (5 original + 3 Phase-10 ruff D-family).

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::dead_link::DeadLinkRule;
use crate::docstring_coverage::DocstringCoverageRule;
use crate::docstring_first_line_imperative::DocstringFirstLineImperativeRule;
use crate::docstring_first_line_period::DocstringFirstLinePeriodRule;
use crate::docstring_signature_drift::DocstringSignatureDriftRule;
use crate::docstring_summary_blank_line::DocstringSummaryBlankLineRule;
use crate::example_doesnt_compile::ExampleDoesntCompileRule;
use crate::readme_install_broken::ReadmeInstallBrokenRule;

/// Built-in Family-16 [`RulePack`] — eight probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinDocsPack;

impl BuiltinDocsPack {
    /// Stable pack id. Distinct from every other built-in pack.
    pub const PACK_ID: &'static str = "cc-builtin-docs";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static README_INSTALL_BROKEN: ReadmeInstallBrokenRule = ReadmeInstallBrokenRule;
static DOCSTRING_SIGNATURE_DRIFT: DocstringSignatureDriftRule = DocstringSignatureDriftRule;
static DOCSTRING_COVERAGE: DocstringCoverageRule = DocstringCoverageRule;
static DEAD_LINK: DeadLinkRule = DeadLinkRule;
static EXAMPLE_DOESNT_COMPILE: ExampleDoesntCompileRule = ExampleDoesntCompileRule;

// Phase 10 (Python long-tail, ruff D-family).
static DOCSTRING_FIRST_LINE_PERIOD: DocstringFirstLinePeriodRule = DocstringFirstLinePeriodRule;
static DOCSTRING_FIRST_LINE_IMPERATIVE: DocstringFirstLineImperativeRule =
    DocstringFirstLineImperativeRule;
static DOCSTRING_SUMMARY_BLANK_LINE: DocstringSummaryBlankLineRule = DocstringSummaryBlankLineRule;

static RULES: &[&'static dyn Rule] = &[
    &README_INSTALL_BROKEN,
    &DOCSTRING_SIGNATURE_DRIFT,
    &DOCSTRING_COVERAGE,
    &DEAD_LINK,
    &EXAMPLE_DOESNT_COMPILE,
    // Phase 10 (Python).
    &DOCSTRING_FIRST_LINE_PERIOD,
    &DOCSTRING_FIRST_LINE_IMPERATIVE,
    &DOCSTRING_SUMMARY_BLANK_LINE,
];

impl RulePack for BuiltinDocsPack {
    fn pack_id(&self) -> &'static str {
        Self::PACK_ID
    }
    fn pack_semver(&self) -> &'static str {
        Self::PACK_SEMVER
    }
    fn kernel_api_min(&self) -> u32 {
        KERNEL_API_VERSION
    }
    fn kernel_api_max(&self) -> Option<u32> {
        None
    }
    fn rules(&self) -> &[&'static dyn Rule] {
        RULES
    }
}
