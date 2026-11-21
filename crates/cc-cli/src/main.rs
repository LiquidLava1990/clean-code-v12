//! `cc` — Phase-1 user-facing binary entry point.
//!
//! Parses argv via clap, dispatches into [`cc_cli::run`], and surfaces
//! the resulting [`cc_cli::ExitCode`] to the OS.

#![forbid(unsafe_code)]

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = cc_cli::Cli::parse();
    let exit = cc_cli::run(cli);
    exit.into()
}
