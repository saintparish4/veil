//! `cargo xtask standards` — OWASP / SWC mapping and SARIF 2.1.0 conformance.
//! Not implemented yet; the subcommand exists so the mapping docs under
//! `benchmarks/standards/` have a runner to grow into.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Skip the Microsoft SARIF multitool invocation even if it is installed.
    #[arg(long)]
    pub skip_multitool: bool,
}

pub fn run(_args: Args) -> Result<()> {
    println!("xtask standards: not implemented yet.");
    Ok(())
}
