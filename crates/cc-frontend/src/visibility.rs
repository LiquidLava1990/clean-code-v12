//! Shared visibility detection — produces the `is_pub` / `is_export` /
//! `visibility` props every frontend stamps on Function / Method / Class /
//! Variable / Module nodes.
//!
//! Each frontend invokes [`detect_visibility`] (or one of the language-
//! specific helpers) and stamps the resulting [`Visibility`] onto the
//! [`cc_cpg::NodeBuilder`] before pushing.
//!
//! ## Why this lives in the shared crate
//!
//! Two of the four frontends (Python, Go) determine visibility from the
//! identifier name alone. Centralising the rule prevents synonym churn
//! between sibling frontends — there is exactly ONE function that decides
//! whether `MyFunc` is exported and ONE that decides whether `_helper`
//! is private.

use cc_cpg::{NodeBuilder, Value};

/// Per-symbol visibility classification used by the dead-code rule and
/// downstream analysers.
///
/// All five fields are emitted as separate node props so rules can match
/// any of:
/// - `is_pub: true` — symbol is callable from outside its current module
/// - `is_export: true` — symbol is exposed via an explicit export keyword
///   (TS/JS only — distinguishes `export function` from a module-internal
///   `function`)
/// - `visibility == "public" | "private" | "crate" | …` — finer-grained
///   classification preserved per language for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Visibility {
    /// Stamped as `is_pub: bool` — true iff the symbol is callable outside
    /// its current compilation unit (Rust `pub*`, Python public name, Go
    /// capital-initial, TS top-level `export`).
    pub is_pub: bool,
    /// Stamped as `is_export: bool` — true iff the symbol carries an
    /// explicit `export` keyword (TypeScript / JavaScript). Always
    /// matches `is_pub` in TS; always `false` for the other three
    /// languages because they have no concept of an `export` keyword.
    pub is_export: bool,
    /// Stamped as `visibility: str` — language-specific descriptor.
    /// Canonical values:
    /// - `"public"` — Rust `pub`, Python normal name, Go capital-initial,
    ///   TS top-level `export`.
    /// - `"private"` — Python `_foo`, TS `private`, Rust no modifier.
    /// - `"protected"` — TS `protected`.
    /// - `"crate"` — Rust `pub(crate)`.
    /// - `"super"` — Rust `pub(super)`.
    /// - `"restricted"` — Rust `pub(in path)`.
    /// - `"package"` — Go lowercase-initial (package-private).
    /// - `"exported"` — Go capital-initial.
    /// - `"name_mangled"` — Python `__foo` (no trailing dunders).
    pub label: &'static str,
}

impl Visibility {
    /// Convenience: pre-canned `private` value the per-language helpers
    /// fall back to when no modifier is present.
    pub const PRIVATE: Self = Self {
        is_pub: false,
        is_export: false,
        label: "private",
    };

    /// Convenience: pre-canned `public` value used by Python public names
    /// and TS exports without finer-grained class-member modifiers.
    pub const PUBLIC: Self = Self {
        is_pub: true,
        is_export: false,
        label: "public",
    };

    /// Stamp this visibility onto a [`NodeBuilder`].
    ///
    /// Adds three props: `is_pub`, `is_export`, `visibility`.
    #[must_use]
    pub fn stamp(self, builder: NodeBuilder) -> NodeBuilder {
        builder
            .with_prop("is_pub", Value::Bool(self.is_pub))
            .with_prop("is_export", Value::Bool(self.is_export))
            .with_prop("visibility", Value::String(self.label.to_owned()))
    }
}

/// Classify a Python identifier by name convention.
///
/// - `_foo` (single leading underscore, no trailing) → private.
/// - `__foo` (two leading underscores, no trailing) → name-mangled (private).
/// - `__foo__` (dunder — leading + trailing) → public (protocol method).
/// - everything else → public.
#[must_use]
pub fn python_visibility(name: &str) -> Visibility {
    if name.starts_with("__") && name.ends_with("__") && name.len() >= 4 {
        return Visibility::PUBLIC;
    }
    if name.starts_with("__") {
        return Visibility {
            is_pub: false,
            is_export: false,
            label: "name_mangled",
        };
    }
    if name.starts_with('_') {
        return Visibility::PRIVATE;
    }
    Visibility::PUBLIC
}

/// Classify a Go identifier by name convention — capital-initial means
/// exported (public outside the package); lowercase-initial means
/// package-private.
#[must_use]
pub fn go_visibility(name: &str) -> Visibility {
    match name.chars().next() {
        Some(c) if c.is_ascii_uppercase() => Visibility {
            is_pub: true,
            is_export: false,
            label: "exported",
        },
        _ => Visibility {
            is_pub: false,
            is_export: false,
            label: "package",
        },
    }
}

/// Map a Rust `visibility_modifier` source slice (e.g. `"pub"`,
/// `"pub(crate)"`, `"pub(super)"`, `"pub(in foo::bar)"`) into a
/// [`Visibility`].
///
/// Pass `None` for items with no modifier — they default to private.
#[must_use]
pub fn rust_visibility(modifier_text: Option<&str>) -> Visibility {
    let Some(text) = modifier_text else {
        return Visibility::PRIVATE;
    };
    let trimmed = text.trim();
    if trimmed == "pub" {
        return Visibility::PUBLIC;
    }
    if trimmed.starts_with("pub(crate)") {
        return Visibility {
            is_pub: true,
            is_export: false,
            label: "crate",
        };
    }
    if trimmed.starts_with("pub(super)") {
        return Visibility {
            is_pub: true,
            is_export: false,
            label: "super",
        };
    }
    if trimmed.starts_with("pub(in ") {
        return Visibility {
            is_pub: true,
            is_export: false,
            label: "restricted",
        };
    }
    if trimmed.starts_with("pub(self)") {
        return Visibility::PRIVATE;
    }
    if trimmed.starts_with("pub") {
        // Catch-all for unfamiliar `pub(...)` forms — treat as public.
        return Visibility::PUBLIC;
    }
    Visibility::PRIVATE
}

/// Classify a TypeScript symbol by combining an enclosing-export flag
/// with an optional class-member access modifier (`"public"`,
/// `"protected"`, `"private"`).
///
/// `is_exported` should be `true` when the symbol's declaration is
/// preceded by `export` / `export default` at module level. The class-
/// member modifier overrides the default "public" classification — a
/// `private` field is never callable from outside even if the enclosing
/// class is exported.
#[must_use]
pub fn typescript_visibility(is_exported: bool, member_modifier: Option<&str>) -> Visibility {
    if let Some(v) = ts_member_modifier_visibility(is_exported, member_modifier) {
        return v;
    }
    if is_exported {
        Visibility {
            is_pub: true,
            is_export: true,
            label: "public",
        }
    } else {
        Visibility::PRIVATE
    }
}

/// Resolve a class-member access modifier (`"private"` / `"protected"` /
/// `"public"`) to its [`Visibility`]. Returns `None` for absent or
/// unrecognised modifiers so the caller can fall back to the
/// enclosing-export classification.
fn ts_member_modifier_visibility(
    is_exported: bool,
    member_modifier: Option<&str>,
) -> Option<Visibility> {
    let modifier = member_modifier?.trim();
    match modifier {
        "private" => Some(Visibility::PRIVATE),
        "protected" => Some(Visibility {
            is_pub: false,
            is_export: false,
            label: "protected",
        }),
        "public" => Some(Visibility {
            is_pub: true,
            is_export: is_exported,
            label: "public",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_dunders_are_public() {
        assert_eq!(python_visibility("__init__"), Visibility::PUBLIC);
        assert_eq!(python_visibility("__call__"), Visibility::PUBLIC);
    }

    #[test]
    fn python_single_underscore_is_private() {
        let v = python_visibility("_helper");
        assert!(!v.is_pub);
        assert_eq!(v.label, "private");
    }

    #[test]
    fn python_double_underscore_is_name_mangled() {
        let v = python_visibility("__secret");
        assert!(!v.is_pub);
        assert_eq!(v.label, "name_mangled");
    }

    #[test]
    fn python_normal_name_is_public() {
        assert_eq!(python_visibility("MyClass"), Visibility::PUBLIC);
        assert_eq!(python_visibility("do_thing"), Visibility::PUBLIC);
    }

    #[test]
    fn go_capital_is_exported() {
        let v = go_visibility("Foo");
        assert!(v.is_pub);
        assert_eq!(v.label, "exported");
    }

    #[test]
    fn go_lowercase_is_package() {
        let v = go_visibility("doThing");
        assert!(!v.is_pub);
        assert_eq!(v.label, "package");
    }

    #[test]
    fn rust_pub_is_public() {
        assert_eq!(rust_visibility(Some("pub")), Visibility::PUBLIC);
    }

    #[test]
    fn rust_pub_crate_is_crate() {
        let v = rust_visibility(Some("pub(crate)"));
        assert!(v.is_pub);
        assert_eq!(v.label, "crate");
    }

    #[test]
    fn rust_pub_super_is_super() {
        let v = rust_visibility(Some("pub(super)"));
        assert!(v.is_pub);
        assert_eq!(v.label, "super");
    }

    #[test]
    fn rust_pub_in_path_is_restricted() {
        let v = rust_visibility(Some("pub(in foo::bar)"));
        assert!(v.is_pub);
        assert_eq!(v.label, "restricted");
    }

    #[test]
    fn rust_no_modifier_is_private() {
        assert_eq!(rust_visibility(None), Visibility::PRIVATE);
    }

    #[test]
    fn ts_exported_is_public() {
        let v = typescript_visibility(true, None);
        assert!(v.is_pub);
        assert!(v.is_export);
        assert_eq!(v.label, "public");
    }

    #[test]
    fn ts_unexported_is_private() {
        let v = typescript_visibility(false, None);
        assert!(!v.is_pub);
        assert_eq!(v.label, "private");
    }

    #[test]
    fn ts_class_private_overrides_export() {
        let v = typescript_visibility(true, Some("private"));
        assert!(!v.is_pub);
        assert_eq!(v.label, "private");
    }

    #[test]
    fn ts_class_protected() {
        let v = typescript_visibility(false, Some("protected"));
        assert_eq!(v.label, "protected");
        assert!(!v.is_pub);
    }
}
