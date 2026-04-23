//! `cargo xtask recall` — implemented in Phase 4.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the labels file (defaults to benchmarks/recall/labels.yaml).
    #[arg(long)]
    pub labels: Option<String>,
}

pub fn run(_args: Args) -> Result<()> {
    println!("xtask recall: not implemented yet (Phase 4).");
    Ok(())
}
