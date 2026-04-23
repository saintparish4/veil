//! `cargo xtask` — Veil benchmarking & release automation runner.
//!
//! Each subcommand maps 1:1 to a `just bench-*` target and writes a committed
//! result artifact under `benchmarks/<area>/results/`. Sub-modules are
//! intentionally minimal in Phase 1: they print a "not implemented yet"
//! message so the workspace + dispatch compile today and every later phase
//! only has to fill in a single file.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cmd {
    pub mod exploits;
    pub mod fetch;
    pub mod perf;
    pub mod precision;
    pub mod recall;
    pub mod standards;
    pub mod triage;
}

/// Top-level CLI parsed from `cargo xtask <subcommand> …`.
#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    about = "Veil benchmarking & release automation runner",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run Criterion perf benches and emit p50/p95/p99 summary JSON.
    Perf(cmd::perf::Args),
    /// Scan the pinned production-DeFi corpus and compute precision.
    Precision(cmd::precision::Args),
    /// Scan the labeled SWC + SmartBugs corpus and compute recall.
    Recall(cmd::recall::Args),
    /// Scan the reconstructed historical-exploit slate.
    Exploits(cmd::exploits::Args),
    /// Validate OWASP / SWC mappings and SARIF 2.1.0 output conformance.
    Standards(cmd::standards::Args),
    /// Populate `benchmarks/vendor/` from the pinned SHAs in corpus.toml.
    Fetch(cmd::fetch::Args),
    /// Classify precision findings into real / false-positive verdicts.
    Triage(cmd::triage::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Perf(args) => cmd::perf::run(args),
        Command::Precision(args) => cmd::precision::run(args),
        Command::Recall(args) => cmd::recall::run(args),
        Command::Exploits(args) => cmd::exploits::run(args),
        Command::Standards(args) => cmd::standards::run(args),
        Command::Fetch(args) => cmd::fetch::run(args),
        Command::Triage(args) => cmd::triage::run(args),
    }
}
