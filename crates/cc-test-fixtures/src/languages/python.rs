//! Embedded byte slices for every Python fixture.
//!
//! Files are sourced from `tests/fixtures/python/**` and embedded at
//! build time via [`include_bytes!`]. The catalog (see
//! `crate::catalog`) references these constants by name.

// ---- shape -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/python/shape/fn_length_violating.py`.
pub const FN_LENGTH_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/fn_length_violating.py");

/// Source bytes for `tests/fixtures/python/shape/fn_length_clean.py`.
pub const FN_LENGTH_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/fn_length_clean.py");

/// Source bytes for `tests/fixtures/python/shape/nesting_violating.py`.
pub const NESTING_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/nesting_violating.py");

/// Source bytes for `tests/fixtures/python/shape/nesting_clean.py`.
pub const NESTING_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/nesting_clean.py");

/// Source bytes for `tests/fixtures/python/shape/params_violating.py`.
pub const PARAMS_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/params_violating.py");

/// Source bytes for `tests/fixtures/python/shape/params_clean.py`.
pub const PARAMS_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/python/shape/params_clean.py");

/// Source bytes for `tests/fixtures/python/shape/duplication_violating.py`.
pub const DUPLICATION_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/duplication_violating.py");

/// Source bytes for `tests/fixtures/python/shape/duplication_clean.py`.
pub const DUPLICATION_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/duplication_clean.py");

/// Source bytes for `tests/fixtures/python/shape/dead_code_violating.py`.
pub const DEAD_CODE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/dead_code_violating.py");

/// Source bytes for `tests/fixtures/python/shape/dead_code_clean.py`.
pub const DEAD_CODE_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/dead_code_clean.py");

/// Source bytes for `tests/fixtures/python/shape/inheritance_violating.py`.
pub const INHERITANCE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/inheritance_violating.py");

/// Source bytes for `tests/fixtures/python/shape/inheritance_clean.py`.
pub const INHERITANCE_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/inheritance_clean.py");

/// Source bytes for `tests/fixtures/python/shape/naming_drift_violating.py`.
pub const NAMING_DRIFT_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/shape/naming_drift_violating.py");

// ---- error -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/python/error/bare_violating.py`.
pub const BARE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/error/bare_violating.py");

/// Source bytes for `tests/fixtures/python/error/bare_clean.py`.
pub const BARE_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/python/error/bare_clean.py");

/// Source bytes for `tests/fixtures/python/error/no_action_violating.py`.
pub const NO_ACTION_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/python/error/no_action_violating.py");

/// Source bytes for `tests/fixtures/python/error/no_action_clean.py`.
pub const NO_ACTION_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/python/error/no_action_clean.py");
