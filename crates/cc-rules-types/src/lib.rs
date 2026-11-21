//! `cc-rules-types` — Family 22 (type system) probe pack.
//!
//! Phase 7 Batch A of Clean Code V12 extends the original three Phase-3
//! probes with ten type-aware async / promise / exhaustiveness probes
//! mined from the OSS delta study. V12 has no full TS type-checker, so
//! every Phase-7 probe ships as a "syntactic shadow" of the canonical
//! ESLint / golangci / clippy rule — high-precision pattern matching on
//! the surface CPG without claiming to replace flow-sensitive
//! type-checking.
//!
//! Probes:
//!
//! Phase 3:
//! - [`implicit_any`] — `Any` / `any` / `interface{}` / `&dyn Any` on a
//!   PUBLIC API surface.
//! - [`unjustified_ignore`] — `# type: ignore` / `// @ts-ignore` /
//!   `#[allow(...)]` without a justification clause.
//! - [`protocol_drift`] — STUB. Real port lands when whole-program
//!   protocol resolution is wired.
//!
//! Phase 7 Batch A:
//! - [`no_floating_promise`] — Promise-returning call dropped on the floor.
//! - [`no_misused_promise`] — Promise used as boolean condition.
//! - [`no_unsafe_argument`] — `any` argument flowing into typed parameter.
//! - [`no_unsafe_return`] — function returns `any` despite typed signature.
//! - [`switch_exhaustiveness`] — switch over identifier without `default:`.
//! - [`lock_held_across_await`] — Rust `MutexGuard` held across `.await`.
//! - [`async_returns_null`] — async fn returns `null` despite `Promise<T>`.
//! - [`await_thenable`] — `await` on a literal / object-literal.
//! - [`no_unnecessary_condition`] — statically constant / redundant condition.
//! - [`exhaustruct`] — Go struct literal missing non-zeroable fields.
//!
//! Phase 9 Batch B (TypeScript-deep-dive ports from typescript-eslint):
//! - [`no_explicit_any`] — declaration site of `: any`.
//! - [`no_non_null_assertion`] — postfix `!` non-null assertion.
//! - [`strict_boolean_expressions`] — string / number used as bare condition.
//! - [`no_base_to_string`] — class-instance coercion without `toString()`.
//! - [`no_confusing_void_expression`] — `void` operator in value position.
//! - [`no_unsafe_enum_comparison`] — comparing members of two distinct enums.
//! - [`ban_ts_comment`] — TS pragma directive without inline description.
//! - [`no_unused_expressions`] — expression statement with no side effect.
//! - [`no_var_requires`] — CommonJS `require(...)` inside a TS file.
//! - [`consistent_type_imports`] — value-import only used in type position.
//!
//! See [`BuiltinTypesPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod async_returns_null;
pub mod await_thenable;
pub mod ban_ts_comment;
pub mod consistent_type_imports;
pub mod exhaustruct;
mod helpers;
pub mod implicit_any;
pub mod lock_held_across_await;
pub mod no_base_to_string;
pub mod no_confusing_void_expression;
pub mod no_explicit_any;
pub mod no_floating_promise;
pub mod no_misused_promise;
pub mod no_non_null_assertion;
pub mod no_unnecessary_condition;
pub mod no_unsafe_argument;
pub mod no_unsafe_enum_comparison;
pub mod no_unsafe_return;
pub mod no_unused_expressions;
pub mod no_var_requires;
mod pack;
pub mod protocol_drift;
pub mod strict_boolean_expressions;
pub mod switch_exhaustiveness;
pub mod unjustified_ignore;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTypesPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTypesPack::PACK_ID;
