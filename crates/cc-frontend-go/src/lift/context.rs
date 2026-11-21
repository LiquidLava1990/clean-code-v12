//! Lift-time context — the source slice + file id, threaded through
//! every lifter so we don't pass them as separate arguments.

use cc_frontend::FileId;

/// Per-file lift context.
pub(crate) struct LiftCtx<'src> {
    /// Borrowed source text; used for `node.utf8_text(source.as_bytes())`.
    pub(crate) source: &'src str,
    /// File identifier propagated onto every node via `file_id`.
    pub(crate) file_id: FileId,
    /// Tracks whether we are currently inside a struct/interface body
    /// (used to disambiguate field-only declarations from top-level ones).
    pub(crate) type_depth: u32,
    /// Whether the function currently being lifted contains a
    /// `go_statement`. Reset for each function. Surfaced on
    /// `Function.lang_ext.goroutine_spawned`.
    pub(crate) goroutine_spawned: bool,
}

impl<'src> LiftCtx<'src> {
    /// Construct a fresh context for a single file lift.
    pub(crate) const fn new(source: &'src str, file_id: FileId) -> Self {
        Self {
            source,
            file_id,
            type_depth: 0,
            goroutine_spawned: false,
        }
    }

    /// Borrow source bytes — convenience for `utf8_text`.
    pub(crate) const fn bytes(&self) -> &'src [u8] {
        self.source.as_bytes()
    }

    /// True when we are at least one type declaration deep.
    #[allow(dead_code)]
    pub(crate) const fn inside_type(&self) -> bool {
        self.type_depth > 0
    }
}
