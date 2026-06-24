# Veil developer, benchmark, and reproducibility entry points.
#
# These targets cover local development and reproducible benchmark runs.
# Benchmark targets delegate to `cargo xtask <subcommand>` so the orchestration
# stays type-checked and works consistently on Linux, macOS, and Windows.

.PHONY: default fmt fmt-check clippy check build build-release test ci \
        bench fetch bench-perf bench-precision bench-recall bench-exploits \
        bench-standards coverage

# Print the available targets by default.
default:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Development.
# ---------------------------------------------------------------------------

fmt: ## Format the workspace
	cargo fmt --all

fmt-check: ## Check formatting without changing files
	cargo fmt --all --check

clippy: ## Lint the workspace with warnings denied
	cargo clippy --workspace --all-targets -- -D warnings

check: ## Type-check the workspace without codegen
	cargo check --workspace --all-targets

build: ## Build the workspace in debug mode
	cargo build --workspace

build-release: ## Build the workspace in release mode
	cargo build --workspace --release

test: ## Run workspace tests
	cargo test --workspace

ci: fmt-check clippy test ## Run local CI checks

# ---------------------------------------------------------------------------
# Reproducibility pipeline.
# ---------------------------------------------------------------------------

# Run the full suite in dependency order.
bench: bench-standards bench-perf bench-precision bench-recall bench-exploits coverage ## Run the full benchmark suite

# Populate `benchmarks/vendor/` from pinned SHAs.
fetch: ## Populate the benchmark vendor tree
	cargo xtask fetch --corpus all

# ---------------------------------------------------------------------------
# Individual suites.
# ---------------------------------------------------------------------------

# Run Criterion performance benches and summarize latency percentiles.
bench-perf: ## Run Criterion performance benches
	cargo xtask perf

# Measure precision on the pinned production-DeFi corpus.
# `cargo xtask precision` auto-hydrates the vendor tree if it is empty
# (see `--no-auto-fetch` to opt out) so this target stays shell-agnostic.
bench-precision: ## Measure precision on the corpus
	cargo xtask precision

# Measure recall against SWC and SmartBugs labels.
bench-recall: ## Measure recall against labels
	cargo xtask recall

# Run historical exploit reconstructions.
bench-exploits: ## Run historical exploit checks
	cargo xtask exploits

# Verify OWASP, SWC, and SARIF conformance.
bench-standards: ## Verify standards conformance
	cargo xtask standards

# Generate line coverage with cargo-llvm-cov.
coverage: ## Generate line coverage report
	cargo llvm-cov --workspace --html --output-dir benchmarks/perf/results/coverage
