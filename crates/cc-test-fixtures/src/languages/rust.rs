//! Embedded byte slices for every Rust fixture.
//!
//! Rust has no class inheritance, so no `cc.shape.no_inheritance`
//! fixture is provided here. See the language-coverage gap noted in
//! [`crate::catalog`].

// ---- shape -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/rust/shape/fn_length_violating.rs`.
pub const FN_LENGTH_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/fn_length_violating.rs");

/// Source bytes for `tests/fixtures/rust/shape/fn_length_clean.rs`.
pub const FN_LENGTH_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/fn_length_clean.rs");

/// Source bytes for `tests/fixtures/rust/shape/nesting_violating.rs`.
pub const NESTING_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/nesting_violating.rs");

/// Source bytes for `tests/fixtures/rust/shape/nesting_clean.rs`.
pub const NESTING_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/rust/shape/nesting_clean.rs");

/// Source bytes for `tests/fixtures/rust/shape/params_violating.rs`.
pub const PARAMS_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/params_violating.rs");

/// Source bytes for `tests/fixtures/rust/shape/params_clean.rs`.
pub const PARAMS_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/rust/shape/params_clean.rs");

/// Source bytes for `tests/fixtures/rust/shape/dead_code_violating.rs`.
pub const DEAD_CODE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/dead_code_violating.rs");

/// Source bytes for `tests/fixtures/rust/shape/dead_code_clean.rs`.
pub const DEAD_CODE_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/rust/shape/dead_code_clean.rs");

// ---- error -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/rust/error/bare_violating.rs`.
pub const BARE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/rust/error/bare_violating.rs");

/// Source bytes for `tests/fixtures/rust/error/bare_clean.rs`.
pub const BARE_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/rust/error/bare_clean.rs");
