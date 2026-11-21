//! `cc-lsp` binary entry — boots the [`cc_lsp::CcLspServer`] over stdio.
//!
//! Argument grammar is intentionally minimal: the only flag we accept is
//! `--stdio` (which is also the default) so the server is symmetric with
//! `rust-analyzer`, `gopls`, and similar daemons. Editor integrations
//! that pass extra flags get a hard error rather than a silent ignore —
//! that's the R-ERR-ACTION discipline the rest of the crate dogfoods.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Boot the server. Returns once the LSP `exit` notification has been
/// processed and `tower-lsp` shuts the underlying socket.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing()?;
    parse_args().context("could not parse cc-lsp argv")?;

    let analyser = Arc::new(Mutex::new(
        cc_lsp::Analyser::new().context("could not initialise cc-lsp analyser")?,
    ));

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) =
        tower_lsp::LspService::new(move |client| cc_lsp::CcLspServer::new(client, analyser));
    tower_lsp::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
    Ok(())
}

/// Parse argv, accepting `--stdio` only (with or without the flag).
///
/// We don't use `clap` here because the surface is tiny and pulling in
/// the dep would be wasteful for one optional positional flag.
fn parse_args() -> anyhow::Result<()> {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--stdio" | "" => {}
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("cc-lsp {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                anyhow::bail!(
                    "unrecognised argument '{other}' — \
                     pass `--stdio` (default) or `--help` to see options"
                );
            }
        }
    }
    Ok(())
}

/// Print the (one-screen) help text.
fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    println!("cc-lsp {version} — Clean Code V12 LSP daemon");
    println!();
    println!("Usage: cc-lsp [--stdio]");
    println!();
    println!("Options:");
    println!("  --stdio       Speak LSP over stdin/stdout (default).");
    println!("  -h, --help    Show this help.");
    println!("  -V, --version Show version.");
}

/// Initialise `tracing` — write to stderr (stdout is reserved for the
/// LSP framed JSON-RPC stream) and respect `RUST_LOG`.
fn install_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|err| anyhow::anyhow!("could not install tracing subscriber: {err}"))?;
    Ok(())
}
