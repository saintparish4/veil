//! `cargo xtask standards` — implemented in Phase 7.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Skip the Microsoft SARIF multitool invocation even if it is installed.
    #[arg(long)]
    pub skip_multitool: bool,
}

pub fn run(_args: Args) -> Result<()> {
    println!("xtask standards: not implemented yet (Phase 7).");
    Ok(())
}
