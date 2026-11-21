//! [`BuiltinI18nA11yPack`] — registers the five Family-15 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::color_only_signal::ColorOnlySignalRule;
use crate::hardcoded_locale::HardcodedLocaleRule;
use crate::keyboard_trap::KeyboardTrapRule;
use crate::missing_alt::MissingAltRule;
use crate::unicode_unsafe_op::UnicodeUnsafeOpRule;

/// Built-in Family-15 [`RulePack`] — five probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinI18nA11yPack;

impl BuiltinI18nA11yPack {
    /// Stable pack id. Distinct from every other built-in pack so the
    /// registry can host them all side-by-side.
    pub const PACK_ID: &'static str = "cc-builtin-i18n-a11y";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static HARDCODED_LOCALE: HardcodedLocaleRule = HardcodedLocaleRule;
static UNICODE_UNSAFE_OP: UnicodeUnsafeOpRule = UnicodeUnsafeOpRule;
static MISSING_ALT: MissingAltRule = MissingAltRule;
static COLOR_ONLY_SIGNAL: ColorOnlySignalRule = ColorOnlySignalRule;
static KEYBOARD_TRAP: KeyboardTrapRule = KeyboardTrapRule;

static RULES: &[&'static dyn Rule] = &[
    &HARDCODED_LOCALE,
    &UNICODE_UNSAFE_OP,
    &MISSING_ALT,
    &COLOR_ONLY_SIGNAL,
    &KEYBOARD_TRAP,
];

impl RulePack for BuiltinI18nA11yPack {
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
