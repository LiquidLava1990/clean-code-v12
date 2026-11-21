#!/usr/bin/env bash
# Re-runnable Cargo workspace scaffold for Clean Code V12.
# Idempotent: only creates missing directories + stub files; never overwrites
# existing crate contents. Safe to run after `cargo new` or manual edits.
#
# Usage: bash tools/scaffold.sh [--force]
#   --force: overwrite existing stubs (DANGER — only use on fresh checkout)

set -euo pipefail

CRATES=(
    cc-cli cc-kernel cc-cpg cc-cpg-store
    cc-frontend cc-frontend-python cc-frontend-typescript
    cc-frontend-go cc-frontend-rust
    cc-incremental cc-rules cc-rules-tier0
    cc-finding cc-sarif cc-rdformat
    cc-baseline cc-fingerprint cc-score
    cc-runtime cc-llm cc-config cc-diagnostics
    cc-lsp cc-test-fixtures
)

FORCE="${1:-}"

repo_root() {
    git rev-parse --show-toplevel 2>/dev/null || pwd
}

cd "$(repo_root)"

ensure_dir() {
    [ -d "$1" ] || mkdir -p "$1"
}

ensure_file() {
    local path="$1"
    local content="$2"
    if [ -f "$path" ] && [ "$FORCE" != "--force" ]; then
        return 0
    fi
    printf '%s\n' "$content" > "$path"
    echo "  + $path"
}

ensure_dir crates examples benches tests docs/architecture docs/rules/tier0
ensure_dir .github/workflows .github/actions/cc-check tools

write_lib_stub() {
    local crate="$1"
    ensure_file "crates/$crate/src/lib.rs" '//! Phase 1 stub. See ../../ARCHITECTURE.md
#![forbid(unsafe_code)]

pub fn placeholder() {}'
}

write_main_stub() {
    local crate="$1"
    ensure_file "crates/$crate/src/main.rs" '//! Phase 1 entry point. See ../../ARCHITECTURE.md
#![forbid(unsafe_code)]

fn main() {
    println!("clean-code-v12 — phase 1 stub");
}'
}

write_lib_cargo() {
    local crate="$1"
    ensure_file "crates/$crate/Cargo.toml" "[package]
name = \"$crate\"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true

[lints]
workspace = true"
}

write_bin_cargo() {
    local crate="$1"
    ensure_file "crates/$crate/Cargo.toml" "[package]
name = \"$crate\"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = \"cc\"
path = \"src/main.rs\"

[dependencies]
anyhow.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
clap.workspace = true

[lints]
workspace = true"
}

for crate in "${CRATES[@]}"; do
    ensure_dir "crates/$crate/src"
    if [ "$crate" = "cc-cli" ]; then
        write_bin_cargo "$crate"
        write_main_stub "$crate"
    else
        write_lib_cargo "$crate"
        write_lib_stub "$crate"
    fi
done

echo "scaffold complete: ${#CRATES[@]} crates verified"
