//! [`BuiltinFormattingPack`] — registers the ten Family-26 formatting probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::bom_present::BomPresentRule;
use crate::crlf_line_endings::CrlfLineEndingsRule;
use crate::inconsistent_string_quotes::InconsistentStringQuotesRule;
use crate::long_line::LongLineRule;
use crate::mixed_indentation::MixedIndentationRule;
use crate::multiple_blank_lines::MultipleBlankLinesRule;
use crate::no_final_newline::NoFinalNewlineRule;
use crate::tab_in_python::TabInPythonRule;
use crate::todo_no_owner::TodoNoOwnerRule;
use crate::trailing_whitespace::TrailingWhitespaceRule;

/// Built-in Family-26 formatting [`RulePack`] — ten Nit-severity probes.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinFormattingPack;

impl BuiltinFormattingPack {
    /// Stable pack id, distinct from every sibling pack so the registry
    /// can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-formatting";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static TRAILING_WHITESPACE: TrailingWhitespaceRule = TrailingWhitespaceRule;
static MIXED_INDENTATION: MixedIndentationRule = MixedIndentationRule;
static TAB_IN_PYTHON: TabInPythonRule = TabInPythonRule;
static CRLF_LINE_ENDINGS: CrlfLineEndingsRule = CrlfLineEndingsRule;
static BOM_PRESENT: BomPresentRule = BomPresentRule;
static NO_FINAL_NEWLINE: NoFinalNewlineRule = NoFinalNewlineRule;
static MULTIPLE_BLANK_LINES: MultipleBlankLinesRule = MultipleBlankLinesRule;
static INCONSISTENT_STRING_QUOTES: InconsistentStringQuotesRule = InconsistentStringQuotesRule;
static LONG_LINE: LongLineRule = LongLineRule;
static TODO_NO_OWNER: TodoNoOwnerRule = TodoNoOwnerRule;

static RULES: &[&'static dyn Rule] = &[
    &TRAILING_WHITESPACE,
    &MIXED_INDENTATION,
    &TAB_IN_PYTHON,
    &CRLF_LINE_ENDINGS,
    &BOM_PRESENT,
    &NO_FINAL_NEWLINE,
    &MULTIPLE_BLANK_LINES,
    &INCONSISTENT_STRING_QUOTES,
    &LONG_LINE,
    &TODO_NO_OWNER,
];

impl RulePack for BuiltinFormattingPack {
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
