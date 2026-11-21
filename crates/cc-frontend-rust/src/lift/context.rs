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
    /// Tracks whether we are currently lifting items inside an `impl_item`
    /// body. Used by [`crate::lift::function::lift_function`] to decide
    /// whether a `function_item` becomes [`cc_cpg::NodeKind::Method`] and to
    /// stamp the receiver type on the method's `lang_ext`.
    pub(crate) impl_depth: u32,
    /// Receiver type (impl block target) — set when entering an `impl_item`,
    /// restored on exit. Empty when not inside an impl.
    pub(crate) receiver_type: String,
}

impl<'src> LiftCtx<'src> {
    pub(crate) const fn new(source: &'src str, file_id: FileId) -> Self {
        Self {
            source,
            file_id,
            impl_depth: 0,
            receiver_type: String::new(),
        }
    }

    /// Borrow source bytes — convenience for `utf8_text`.
    pub(crate) const fn bytes(&self) -> &'src [u8] {
        self.source.as_bytes()
    }

    /// True when we are at least one `impl_item` deep.
    pub(crate) const fn inside_impl(&self) -> bool {
        self.impl_depth > 0
    }
}
