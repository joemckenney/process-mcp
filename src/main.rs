use anyhow::{Context, Result};
use process_mcp::mcp::server::ProcessServer;
use rmcp::{transport::stdio, ServiceExt};
use std::path::PathBuf;

const DEFAULT_PROC_ROOT: &str = "/proc";

#[tokio::main]
async fn main() -> Result<()> {
    let proc_root = parse_args()?;
    let service = ProcessServer::new(proc_root)
        .serve(stdio())
        .await
        .context("starting MCP service over stdio")?;
    service.waiting().await.context("running MCP service")?;
    Ok(())
}

fn parse_args() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let mut proc_root: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--proc-root" => {
                let v = args
                    .next()
                    .context("--proc-root requires a path argument")?;
                proc_root = Some(PathBuf::from(v));
            }
            "--help" | "-h" => {
                eprintln!("process-mcp [--proc-root <path>]");
                eprintln!();
                eprintln!("  --proc-root  procfs root (default: {DEFAULT_PROC_ROOT})");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    Ok(proc_root.unwrap_or_else(|| PathBuf::from(DEFAULT_PROC_ROOT)))
}
