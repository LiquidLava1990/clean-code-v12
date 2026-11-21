//! Embedded byte slices for every Go fixture.

// ---- shape -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/go/shape/fn_length_violating.go`.
pub const FN_LENGTH_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/fn_length_violating.go");

/// Source bytes for `tests/fixtures/go/shape/fn_length_clean.go`.
pub const FN_LENGTH_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/fn_length_clean.go");

/// Source bytes for `tests/fixtures/go/shape/nesting_violating.go`.
pub const NESTING_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/nesting_violating.go");

/// Source bytes for `tests/fixtures/go/shape/nesting_clean.go`.
pub const NESTING_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/go/shape/nesting_clean.go");

/// Source bytes for `tests/fixtures/go/shape/params_violating.go`.
pub const PARAMS_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/params_violating.go");

/// Source bytes for `tests/fixtures/go/shape/params_clean.go`.
pub const PARAMS_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/go/shape/params_clean.go");

/// Source bytes for `tests/fixtures/go/shape/dead_code_violating.go`.
pub const DEAD_CODE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/dead_code_violating.go");

/// Source bytes for `tests/fixtures/go/shape/dead_code_clean.go`.
pub const DEAD_CODE_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/go/shape/dead_code_clean.go");

// ---- error -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/go/error/bare_violating.go`.
pub const BARE_VIOLATING: &[u8] = include_bytes!("../../tests/fixtures/go/error/bare_violating.go");

/// Source bytes for `tests/fixtures/go/error/bare_clean.go`.
pub const BARE_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/go/error/bare_clean.go");
