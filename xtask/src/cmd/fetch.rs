//! `cargo xtask fetch` — implemented in Phase 3 (populates `benchmarks/vendor/`).

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Which corpus to hydrate: `precision`, `recall`, or `all`.
    #[arg(long, default_value = "all")]
    pub corpus: String,
}

pub fn run(_args: Args) -> Result<()> {
    println!("xtask fetch: not implemented yet (Phase 3).");
    Ok(())
}
