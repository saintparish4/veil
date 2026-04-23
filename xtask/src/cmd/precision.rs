//! `cargo xtask precision` — implemented in Phase 3.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Permit untriaged finding IDs (CI blocks on them by default).
    #[arg(long)]
    pub allow_untriaged: bool,
    /// Optional comparator tool (e.g. `slither`).
    #[arg(long)]
    pub compare: Option<String>,
}

pub fn run(_args: Args) -> Result<()> {
    println!("xtask precision: not implemented yet (Phase 3).");
    Ok(())
}
