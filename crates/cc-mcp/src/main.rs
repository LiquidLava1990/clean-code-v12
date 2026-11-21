//! `cc-mcp` — Model Context Protocol stdio entry point.
//!
//! Reads newline-delimited JSON-RPC 2.0 from stdin, writes responses
//! to stdout. Tracing goes to stderr so it never pollutes the protocol
//! channel.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    init_tracing();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("error: cannot build tokio runtime: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(cc_mcp::run_stdio()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: stdio loop failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
