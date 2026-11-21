//! Lift-time context — the source slice + the file id, threaded through
//! every lifter so we don't pass them as separate arguments.
//!
//! The context is **not** a place for accumulated state about already-lifted
//! nodes. Per-language passes live in `cc_frontend::default_resolver` and
//! similar post-pass crates so the lift step stays simple and parallel-safe
//! at the file level.

use cc_frontend::FileId;

/// Per-file lift context.
pub(crate) struct LiftCtx<'src> {
    /// Borrowed source text. Used to extract identifier names + literal
    /// content via `node.utf8_text(source.as_bytes())`.
    pub(crate) source: &'src str,
    /// File identifier — propagated onto every node via `file_id`.
    pub(crate) file_id: FileId,
    /// Tracks whether we are currently inside a class body. Used by
    /// [`crate::lift::function::lift_function`] to mark `is_method`.
    pub(crate) class_depth: u32,
}

impl<'src> LiftCtx<'src> {
    pub(crate) const fn new(source: &'src str, file_id: FileId) -> Self {
        Self {
            source,
            file_id,
            class_depth: 0,
        }
    }

    /// Borrow source bytes — convenience for `utf8_text`.
    pub(crate) const fn bytes(&self) -> &'src [u8] {
        self.source.as_bytes()
    }

    /// True when we are at least one `class_definition` deep.
    pub(crate) const fn inside_class(&self) -> bool {
        self.class_depth > 0
    }
}
