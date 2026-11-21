//! `cc-rules-taint` — Family 4 (taint / security flow) probe pack.
//!
//! Phase 3 + Phase 10 of Clean Code V12. Ships fifteen probes:
//!
//! - [`sql_injection`] — tainted value reaches a string-formatted SQL
//!   query API.
//! - [`xss`] — tainted value reaches an HTML-rendering response without
//!   escaping.
//! - [`command_injection`] — tainted value reaches a shell-exec sink.
//! - [`unsafe_deserialization`] — tainted bytes reach an unsafe
//!   deserializer (e.g. `yaml.load` without `SafeLoader`).
//! - [`path_traversal`] — tainted value reaches a filesystem path API
//!   without normalization.
//! - [`repr_on_untrusted`] — R-05: tainted value formatted via
//!   `repr` / `%r` / `{:?}` / `JSON.stringify`.
//! - [`ssrf`] — tainted value used as the URL of an outbound HTTP
//!   request.
//!
//! Phase 10 (Batch L — multi-language cross-cutting probes mined from
//! CodeQL, Sonar, and Semgrep universal patterns):
//!
//! - [`weak_password_hash`] — MD5 / SHA-1 used near a credential token.
//! - [`path_traversal_join`] — `path.join(BASE, request.x)` syntactic
//!   pattern (sister probe to value-flow [`path_traversal`]).
//! - [`eval_dynamic_code`] — dynamic-eval sink across Python / JS /
//!   Ruby.
//!
//! Phase 10 (Go gosec security probes):
//!
//! - [`gosec_sql_concat`] — Go `db.Query`/`Exec` with `+`-concat or
//!   `fmt.Sprintf` first arg (gosec G201/G202).
//! - [`gosec_command_injection_exec`] — Go `exec.Command` with a
//!   non-literal program name (gosec G204).
//! - [`gosec_unsafe_pointer_use`] — Go `unsafe.Pointer(...)` call
//!   (gosec G103).
//! - [`gosec_template_html_unescaped`] — Go `template.HTML` /
//!   `template.JS` / `template.URL` wrapper on a non-literal value
//!   (gosec G203).
//! - [`gosec_filepath_traversal`] — Go file open/read called with a
//!   function parameter (gosec G304).
//!
//! See [`BuiltinTaintPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Phase-3 dataflow scope
//!
//! Detection is **same-function** only: a per-function tainted-set is
//! built top-down by [`helpers::build_tainted_set`], propagating through
//! `Write` and `Call` parent chains and removed at sanitizer sites.
//! Cross-function taint is deferred to Phase 4 once the call-graph
//! resolver lands.
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod _go_syntax;
pub mod command_injection;
pub mod eval_dynamic_code;
pub mod gosec_command_injection_exec;
pub mod gosec_filepath_traversal;
pub mod gosec_sql_concat;
pub mod gosec_template_html_unescaped;
pub mod gosec_unsafe_pointer_use;
mod helpers;
mod pack;
pub mod path_traversal;
pub mod path_traversal_join;
pub mod repr_on_untrusted;
pub mod sql_injection;
pub mod ssrf;
pub mod unsafe_deserialization;
pub mod weak_password_hash;
pub mod xss;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTaintPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTaintPack::PACK_ID;
