//! Salsa input structs — the cache-invalidation surface.
//!
//! Inputs are the entry points: anything not derivable from an input must
//! come **from** an input. When an input field changes via `Setter` the
//! tracked function cache for everything downstream is invalidated.
//!
//! # Design
//!
//! - [`FileInput`] — one per source file. `content_hash` is the
//!   invalidation signal: same hash -> cache hit; different hash ->
//!   recompute `parsed_tree` / `cpg_root` / `findings_for` /
//!   `health_score`. `content` is carried so tracked queries can read
//!   bytes without re-touching disk on every revision.
//! - [`RepoInput`] — one per repo. `file_set` is a `BTreeSet<u64>` of
//!   `FileInput` salsa ids; adding/removing a file changes the set and
//!   invalidates `repo_health_score`.
//! - [`RuleInput`] — one per loaded rule. Bumping `pack_semver` (e.g. on
//!   probe-pack upgrade) invalidates `findings_for` for every file that
//!   used that rule.
#![allow(missing_docs)]

use std::collections::BTreeSet;

use camino::Utf8PathBuf;
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 content hash. Equality compares all 32 bytes.
///
/// We use SHA-256 (not blake3) because it lines up with `cc-cpg-store`'s
/// path-hashing scheme and keeps the dependency surface narrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Hash a byte slice into a [`ContentHash`].
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }
}

// SAFETY: ContentHash is a `[u8; 32]` newtype with total structural
// equality and no interior mutability or borrowed data. The impl follows
// the same shape as salsa's stock `unsafe impl Update for [T; N]`.
impl_salsa_update_eq!(ContentHash);

// SAFETY: `Utf8PathBuf` is a `String` newtype (camino guarantees UTF-8
// invariant). Total structural equality, no borrows, no interior
// mutability — same shape as salsa's stock `String` impl.
impl_salsa_update_eq!(Utf8PathBufWrap; .0);

/// Newtype wrapper over [`Utf8PathBuf`] carrying a manual [`salsa::Update`]
/// impl. Camino does not provide one upstream and we must own this type
/// to add the impl (orphan rule).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Utf8PathBufWrap(pub Utf8PathBuf);

impl From<Utf8PathBuf> for Utf8PathBufWrap {
    fn from(p: Utf8PathBuf) -> Self {
        Self(p)
    }
}

impl From<&str> for Utf8PathBufWrap {
    fn from(s: &str) -> Self {
        Self(Utf8PathBuf::from(s))
    }
}

/// A source file participating in incremental analysis.
///
/// `content_hash` is the cache key: when it changes, every tracked query
/// taking this `FileInput` reruns. `content` carries the actual bytes
/// (so `parsed_tree` doesn't need to re-read disk every revision); the
/// language tag picks the frontend.
/// Salsa input struct — see module docs.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::input]
pub struct FileInput {
    /// Repo-relative path, as a [`Utf8PathBuf`] (wrapped for `Update`).
    #[return_ref]
    pub path: Utf8PathBufWrap,

    /// Cache-invalidation signal. Updated via [`crate::CcDatabase::update_file`].
    pub content_hash: ContentHash,

    /// Source bytes for this revision. Stored so queries are pure
    /// (don't touch disk) once the input is registered.
    #[return_ref]
    pub content: String,

    /// Language tag matching `cc_frontend::LanguageFrontend::language_name`.
    /// Held as `String` because `&'static str` is not `salsa::Update` (refs
    /// into the database are forbidden by the `Update` trait safety doc).
    #[return_ref]
    pub language: String,
}

/// A repository participating in cross-file analysis.
///
/// `file_set` invalidates `repo_health_score` when files are
/// added/removed; per-file scores remain cached because they key on
/// `FileInput`, not on `RepoInput`.
/// Salsa input struct — see module docs.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::input]
pub struct RepoInput {
    /// Absolute repo root (wrapped for `Update`).
    #[return_ref]
    pub root: Utf8PathBufWrap,

    /// Set of FileInput salsa ids in this repo. We use `u64` (the salsa
    /// id) rather than `FileInput` itself because keying a `BTreeSet` on
    /// the salsa-generated tracked struct entangles the database
    /// lifetime; the `u64` ids round-trip cleanly.
    #[return_ref]
    pub file_ids: BTreeSet<u64>,
}

/// A rule (probe) participating in `findings_for`.
///
/// Bumping `pack_semver` invalidates the entire findings cache for every
/// file the rule pack covers. `rule_id` is stable across upgrades.
/// Salsa input struct — see module docs.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::input]
pub struct RuleInput {
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`.
    #[return_ref]
    pub rule_id: String,

    /// Probe pack semver string. Bumping invalidates findings.
    #[return_ref]
    pub pack_semver: String,
}
