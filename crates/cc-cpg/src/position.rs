//! Source-position primitives.
//!
//! Lines and columns are **1-indexed**, byte offset is **0-indexed**.
//! `Position { line: 1, column: 1, offset: 0 }` is the first byte of a file.

use serde::{Deserialize, Serialize};

/// A point in a source file.
///
/// Lines and columns are 1-indexed (matches LSP / editor convention); the
/// byte offset is 0-indexed (matches tree-sitter and slice indexing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Position {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed column number (counted in UTF-16 code units to match LSP).
    pub column: u32,
    /// 0-indexed byte offset from start of file.
    pub offset: u32,
}

impl Position {
    /// First byte of a file: `line = 1, column = 1, offset = 0`.
    #[must_use]
    pub const fn start_of_file() -> Self {
        Self {
            line: 1,
            column: 1,
            offset: 0,
        }
    }

    /// Construct a position with explicit fields.
    ///
    /// Use [`Position::start_of_file`] for the file-origin sentinel.
    #[must_use]
    pub const fn new(line: u32, column: u32, offset: u32) -> Self {
        Self {
            line,
            column,
            offset,
        }
    }
}

/// A half-open `[start, end)` range in a source file.
///
/// Both endpoints share the [`Position`] indexing convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Range {
    /// Inclusive start.
    pub start: Position,
    /// Exclusive end.
    pub end: Position,
}

impl Range {
    /// Construct a range. `end` should not precede `start`; this invariant is
    /// enforced by frontend lifters, not at the type level.
    #[must_use]
    pub const fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }

    /// Byte length of the range.
    #[must_use]
    pub const fn byte_len(&self) -> u32 {
        self.end.offset.saturating_sub(self.start.offset)
    }
}
