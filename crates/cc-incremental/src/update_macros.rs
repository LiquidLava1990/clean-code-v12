//! Internal macros for the salsa `Update` trait boilerplate.
//!
//! Salsa requires `unsafe impl salsa::Update` on every type that flows
//! through a tracked query. The bodies are mechanical:
//!
//! - For value-equality types (`PartialEq + Eq`): "if old == new -> false,
//!   else replace + return true".
//! - For `Arc`-wrapped foreign types where structural eq isn't available:
//!   "if `Arc::ptr_eq(&old.0, &new.0)` -> false, else replace + return true".
//!
//! Hand-writing four copies of each was producing self-host duplication
//! findings (cc.shape.duplication) on cc-incremental. These macros emit
//! exactly the same code each impl had — the rule never sees the
//! expansion as separate functions because the macro hides them behind
//! one declaration site each.
//!
//! # Safety contract (shared by both macros)
//!
//! `salsa::Update::maybe_update`'s caller-side contract guarantees
//! `old_pointer` is a unique writable pointer to a live `Self` for the
//! duration of the call. The expansions only ever produce a single
//! `&mut *old_pointer` borrow per call and never alias it. See the
//! salsa docs for the upstream invariants.

/// Implement `salsa::Update` for a type whose equality test is
/// structural (`PartialEq + Eq`). Both `ContentHash` and the
/// `Utf8PathBufWrap` newtype (whose `eq` reduces to inner string
/// equality) qualify.
///
/// Usage:
/// ```ignore
/// impl_salsa_update_eq!(ContentHash);          // via `*old == new_value`
/// impl_salsa_update_eq!(Utf8PathBufWrap; .0);  // via `old.0 == new_value.0`
/// ```
macro_rules! impl_salsa_update_eq {
    ($ty:ty) => {
        #[allow(unsafe_code)]
        unsafe impl salsa::Update for $ty {
            unsafe fn maybe_update(old_pointer: *mut Self, new_value: Self) -> bool {
                // SAFETY: salsa's caller contract guarantees `old_pointer`
                // is a unique writable pointer to a live `Self` for the
                // duration of this call.
                let old = unsafe { &mut *old_pointer };
                if *old == new_value {
                    false
                } else {
                    *old = new_value;
                    true
                }
            }
        }
    };
    ($ty:ty; .$field:tt) => {
        #[allow(unsafe_code)]
        unsafe impl salsa::Update for $ty {
            unsafe fn maybe_update(old_pointer: *mut Self, new_value: Self) -> bool {
                // SAFETY: salsa's caller contract guarantees `old_pointer`
                // is a unique writable pointer to a live `Self` for the
                // duration of this call.
                let old = unsafe { &mut *old_pointer };
                if old.$field == new_value.$field {
                    false
                } else {
                    *old = new_value;
                    true
                }
            }
        }
    };
}

/// Implement `salsa::Update` for an `Arc`-wrapped foreign type using
/// `Arc::ptr_eq` for the no-op fast path. The wrapper's single field
/// must be `Arc<T>` and accessible at `.0`. Replacement is sound
/// because the salsa runtime only calls this when handing a freshly-
/// produced value; no aliased `&T` outside the database can exist
/// (`Update`'s safety doc forbids `&'db T` references).
macro_rules! impl_salsa_update_arc_ptr_eq {
    ($ty:ty) => {
        #[allow(unsafe_code)]
        unsafe impl salsa::Update for $ty {
            unsafe fn maybe_update(old_pointer: *mut Self, new_value: Self) -> bool {
                // SAFETY: salsa's caller contract guarantees `old_pointer`
                // is a unique writable pointer to a live `Self` for the
                // duration of this call.
                let old = unsafe { &mut *old_pointer };
                if std::sync::Arc::ptr_eq(&old.0, &new_value.0) {
                    false
                } else {
                    *old = new_value;
                    true
                }
            }
        }
    };
}
