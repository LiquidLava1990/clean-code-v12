//! `ccv12-pre-commit` — the `ccv12` CLI under a name pre-commit can install.
//!
//! pre-commit's `language: rust` runs `cargo install --path .` at the
//! repository root, which needs a root package. This shim is that
//! package's binary: it is byte-for-byte the same CLI as `ccv12`, named
//! differently so it never collides with `cc-cli`'s `ccv12` binary in the
//! shared `target/` directory.

#![forbid(unsafe_code)]

use clap::Parser;

fn main() -> std::process::ExitCode {
    cc_cli::run(cc_cli::Cli::parse()).into()
}
