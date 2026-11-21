//! Embedded byte slices for every TypeScript fixture.

// ---- shape -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/typescript/shape/fn_length_violating.ts`.
pub const FN_LENGTH_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/fn_length_violating.ts");

/// Source bytes for `tests/fixtures/typescript/shape/fn_length_clean.ts`.
pub const FN_LENGTH_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/fn_length_clean.ts");

/// Source bytes for `tests/fixtures/typescript/shape/nesting_violating.ts`.
pub const NESTING_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/nesting_violating.ts");

/// Source bytes for `tests/fixtures/typescript/shape/nesting_clean.ts`.
pub const NESTING_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/nesting_clean.ts");

/// Source bytes for `tests/fixtures/typescript/shape/params_violating.ts`.
pub const PARAMS_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/params_violating.ts");

/// Source bytes for `tests/fixtures/typescript/shape/params_clean.ts`.
pub const PARAMS_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/params_clean.ts");

/// Source bytes for `tests/fixtures/typescript/shape/inheritance_violating.ts`.
pub const INHERITANCE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/inheritance_violating.ts");

/// Source bytes for `tests/fixtures/typescript/shape/inheritance_clean.ts`.
pub const INHERITANCE_CLEAN: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/inheritance_clean.ts");

/// Source bytes for `tests/fixtures/typescript/shape/naming_drift_violating.ts`.
pub const NAMING_DRIFT_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/shape/naming_drift_violating.ts");

// ---- error -----------------------------------------------------------------

/// Source bytes for `tests/fixtures/typescript/error/bare_violating.ts`.
pub const BARE_VIOLATING: &[u8] =
    include_bytes!("../../tests/fixtures/typescript/error/bare_violating.ts");

/// Source bytes for `tests/fixtures/typescript/error/bare_clean.ts`.
pub const BARE_CLEAN: &[u8] = include_bytes!("../../tests/fixtures/typescript/error/bare_clean.ts");
