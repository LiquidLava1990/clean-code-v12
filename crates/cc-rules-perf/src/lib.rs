//! `cc-rules-perf` — Family 2 (static performance) probe pack.
//!
//! Ships twenty-four adoption-friendly performance probes (Phase 1 + 9 + 10 + 12).
//! Every rule defaults to [`cc_finding::Severity::Required`]; perf
//! findings nudge, never block.
//!
//! # Probes
//!
//! - `cc.perf.n_plus_one_orm` — ORM `objects.all()` / `.filter()` calls inside
//!   a loop, missing `prefetch_related` / `select_related` / `joinedload`.
//! - `cc.perf.sync_in_async` — blocking sync calls (`time.sleep`,
//!   `requests.get`, `fs.readFileSync`, `std::fs::read`, ...) inside an
//!   `async` function.
//! - `cc.perf.alloc_in_loop` — heap-allocating constructor (`Vec::new`,
//!   `HashMap::new`, `Box::new`, `dict()`, ...) in a loop body whose binding
//!   is reused only inside the same loop.
//! - `cc.perf.wrong_collection` — membership lookup against a literal list
//!   with > 3 elements (use a set / hash map).
//! - `cc.perf.regex_compile_in_loop` — `re.compile` / `Regex::new` /
//!   `regexp.MustCompile` / `new RegExp` inside a loop body.
//! - `cc.perf.missing_memoization` — pure helper called > 3 times from one
//!   caller body with no I/O signature words in its name.
//! - `cc.perf.gil_trap` — Python `async def` with > 20 lines of body and no
//!   `await` descendant — the coroutine never yields.
//! - `cc.perf.gc_pressure` — list-comprehension materialised solely to be
//!   consumed by a single-shot reducer (`sum`, `max`, `min`, `any`, `all`).
//! - `cc.perf.string_concat_loop` — `s = s + ...` / `s += ...` with a
//!   string-named LHS inside a loop body.
//!
//! Phase 9 (Go-deep-dive — golangci):
//!
//! - `cc.perf.makezero_with_append` — `make([]T, n)` followed by
//!   `append(s, ...)` (creates n zeros then grows).
//! - `cc.perf.prealloc_slice_in_loop` — slice grown in `range` loop
//!   without `make([]T, 0, n)` capacity hint.
//! - `cc.perf.no_context_in_http` — `http.NewRequest` used where
//!   `http.NewRequestWithContext` belongs.
//! - `cc.perf.wasted_assign` — `x := 1; x = 2; use(x)` where the `:= 1`
//!   is dead.
//!
//! Phase 9 (Rust-deep-dive — clippy):
//!
//! - `cc.perf.cloned_instead_of_copied` — `.iter().cloned()` over a
//!   `Copy` element (clippy `cloned_instead_of_copied`).
//! - `cc.perf.cmp_owned` — `s == "lit".to_string()` (clippy
//!   `cmp_owned`).
//! - `cc.perf.box_collection` — `Box<Vec<T>>` etc (clippy
//!   `box_collection`).
//! - `cc.perf.boxed_local` — `fn f(x: Box<T>)` for concrete `T` (clippy
//!   `boxed_local`).
//! - `cc.perf.branches_sharing_code` — if/else branches share trailing
//!   line (clippy `branches_sharing_code`).
//!
//! Phase 10 (Rust long-tail — clippy):
//!
//! - `cc.perf.collection_is_never_read` — local `Vec`/`HashMap`/...
//!   declared, mutated, never observed (clippy `collection_is_never_read`).
//! - `cc.perf.useless_collect` — `.collect()` immediately fed back into
//!   `.iter()` / `.into_iter()` (clippy `needless_collect`).
//! - `cc.perf.format_in_format_args` — nested `format!(...)` inside an
//!   outer formatter macro (clippy `format_in_format_args`).
//!
//! Phase 12 (final OSS long-tail sweep):
//!
//! - `cc.perf.regex_compile_in_function` — `re.compile("...")` inside
//!   a Python function body (compiles per call).
//! - `cc.perf.string_concat_in_recursion` — Python / JS function that
//!   concatenates strings AND recurses into itself (quadratic).
//! - `cc.perf.dict_iteration_with_keys` — `for k in d.keys():` /
//!   `x in d.keys()` (ruff PERF102 / SIM118).
//!
//! # Stub status
//!
//! Phase-1 frontends do not yet emit several signals these probes need
//! (`element_count` on array literals, reliable string-typed bindings,
//! `await` descendants). Probes that would require those signals to fire
//! correctly ship as stubs that register the rule id but return an empty
//! [`Vec`]; each stub carries a `// TODO(phase-3): wire <signal>` comment
//! pointing at the missing dependency. See [`pack::BuiltinPerfPack`] —
//! every advertised rule id is registered today, even when its detection
//! logic is parked.
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`); no
//! function exceeds 50 LOC; nesting stays shallow; no bare `unwrap` /
//! `expect` outside tests; every error sentence ends with what the user
//! should do next (R-ERR-ACTION).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub(crate) mod alloc_in_loop;
pub(crate) mod box_collection;
pub(crate) mod boxed_local;
pub(crate) mod branches_sharing_code;
pub(crate) mod cloned_instead_of_copied;
pub(crate) mod cmp_owned;
pub(crate) mod collection_is_never_read;
pub(crate) mod dict_iteration_with_keys;
pub(crate) mod format_in_format_args;
pub(crate) mod gc_pressure;
pub(crate) mod gil_trap;
pub(crate) mod helpers;
pub(crate) mod makezero_with_append;
pub(crate) mod missing_memoization;
pub(crate) mod n_plus_one_orm;
pub(crate) mod no_context_in_http;
mod pack;
pub(crate) mod prealloc_slice_in_loop;
pub(crate) mod regex_compile_in_function;
pub(crate) mod regex_compile_in_loop;
pub(crate) mod string_concat_in_recursion;
pub(crate) mod string_concat_loop;
pub(crate) mod sync_in_async;
pub(crate) mod useless_collect;
pub(crate) mod wasted_assign;
pub(crate) mod wrong_collection;

#[cfg(test)]
mod tests;

pub use pack::BuiltinPerfPack;

/// Re-export of the canonical pack id, mirrored for downstream tests.
pub const PACK_ID: &str = BuiltinPerfPack::PACK_ID;
