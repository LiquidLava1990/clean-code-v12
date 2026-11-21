//! Phase 10 safety + coverage probes (2).
//!
//! Detects two structural-completeness gaps the other Family-25
//! sub-families don't cover:
//!
//! - [`public_fn_no_test`] — public exported function with no
//!   workspace-visible test naming the function. Heuristic, single-file
//!   scan only — Phase-10 stance.
//! - [`unsafe_block_no_safety_comment`] — Rust `unsafe { ... }` without
//!   the doctrine-required `// SAFETY:` comment immediately above.

pub mod public_fn_no_test;
pub mod unsafe_block_no_safety_comment;
