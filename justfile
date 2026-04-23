# Veil — benchmarking & reproducibility entry points.
#
# Human-facing targets delegate to `cargo xtask <subcommand>` so all the
# logic is type-checked Rust that works identically on Linux / macOS /
# Windows. Every headline number in README.md is regenerable by exactly
# one of the targets below.

set windows-shell := ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

# Default target: print the available recipes.
default:
    @just --list

# ---------------------------------------------------------------------------
# Reproducibility pipeline (Phase 8 wires this up end-to-end).
# ---------------------------------------------------------------------------

# Run the full suite in dependency order. Used by the nightly CI workflow.
bench: bench-standards bench-perf bench-precision bench-recall bench-exploits coverage

# Populate `benchmarks/vendor/` from pinned SHAs (Phase 3).
fetch:
    cargo xtask fetch --corpus all

# ---------------------------------------------------------------------------
# Individual suites.
# ---------------------------------------------------------------------------

# Criterion perf benches + p50/p95/p99 summary (Phase 2).
bench-perf:
    cargo xtask perf

# Precision on the pinned production-DeFi corpus (Phase 3).
bench-precision:
    cargo xtask precision

# Recall against SWC + SmartBugs labels (Phase 4).
bench-recall:
    cargo xtask recall

# Historical-exploit reconstructions (Phase 5).
bench-exploits:
    cargo xtask exploits

# OWASP / SWC / SARIF conformance (Phase 7).
bench-standards:
    cargo xtask standards

# Line coverage via cargo-llvm-cov (Phase 6).
coverage:
    cargo llvm-cov --workspace --html --output-dir benchmarks/perf/results/coverage
