# Veil — benchmarking & reproducibility entry points.
#
# Human-facing targets delegate to `cargo xtask <subcommand>` so all the
# logic is type-checked Rust that works identically on Linux / macOS /
# Windows. Every headline number in README.md is regenerable by exactly
# one of the targets below.

.PHONY: default bench fetch bench-perf bench-precision bench-recall \
        bench-exploits bench-standards coverage

# Default target: print the available targets.
default:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Reproducibility pipeline (Phase 8 wires this up end-to-end).
# ---------------------------------------------------------------------------

# Run the full suite in dependency order. Used by the nightly CI workflow.
bench: bench-standards bench-perf bench-precision bench-recall bench-exploits coverage ## Run the full benchmark suite

# Populate `benchmarks/vendor/` from pinned SHAs (Phase 3).
fetch: ## Populate benchmarks/vendor/ from pinned SHAs
	cargo xtask fetch --corpus all

# ---------------------------------------------------------------------------
# Individual suites.
# ---------------------------------------------------------------------------

# Criterion perf benches + p50/p95/p99 summary (Phase 2).
bench-perf: ## Criterion perf benches + p50/p95/p99 summary
	cargo xtask perf

# Precision on the pinned production-DeFi corpus (Phase 3).
# `cargo xtask precision` auto-hydrates the vendor tree if it is empty
# (see `--no-auto-fetch` to opt out) so this target stays shell-agnostic.
bench-precision: ## Precision on the pinned production-DeFi corpus
	cargo xtask precision

# Recall against SWC + SmartBugs labels (Phase 4).
bench-recall: ## Recall against SWC + SmartBugs labels
	cargo xtask recall

# Historical-exploit reconstructions (Phase 5).
bench-exploits: ## Historical-exploit reconstructions
	cargo xtask exploits

# OWASP / SWC / SARIF conformance (Phase 7).
bench-standards: ## OWASP / SWC / SARIF conformance
	cargo xtask standards

# Line coverage via cargo-llvm-cov (Phase 6).
coverage: ## Line coverage via cargo-llvm-cov
	cargo llvm-cov --workspace --html --output-dir benchmarks/perf/results/coverage
