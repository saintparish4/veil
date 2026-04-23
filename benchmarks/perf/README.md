# Performance benchmarks

Criterion-driven measurements of the full scan pipeline (parse → detectors
→ suppression) on every fixture the repo ships, plus three synthetic
size-scaling fixtures generated in-memory.

## Ownership by phase

| Artifact | Populated by | Status |
|---|---|---|
| `results/summary.json` — per-bench mean/median/p50/p95/p99 over `scan_file/*` | **Phase 2** (`just bench-perf`) | Populated — see table below |
| `results/summary.json` — `aggregate.corpus_median_ns`, `aggregate.corpus_elements` | **Phase 3** (`just fetch && just bench-perf`) after the precision corpus is vendored into `benchmarks/vendor/precision/` | `null` until Phase 3 lands |
| `results/comparison.md` — wall-time vs. Slither | **Phase 2 optional** (`cargo xtask perf --compare slither`), requires Docker | Not generated — opt-in flag |
| Criterion HTML per bench | **Phase 2** (`cargo bench -p veil --bench scan_bench`) | Regenerated in place, not committed |

The companion runner lives in [`xtask/src/cmd/perf.rs`](../../xtask/src/cmd/perf.rs);
the bench source is [`core/benches/scan_bench.rs`](../../core/benches/scan_bench.rs).

## Headline numbers

Computed from [`results/summary.json`](results/summary.json)
(git `9add466`, generated 2026-04-23):

| Metric | Value | Source field |
|---|---|---|
| Median per-contract scan time | **~4.03 ms** | `aggregate.scan_file_median_of_medians_ns` |
| p99 across 18 real fixtures | **< 10 ms** (max 9.85 ms, `cfg_false_positive_regression`) | `benches[scan_file/<real>].p99_ns` |
| Fixtures measured | 21 (18 real + 3 synthetic) | `aggregate.scan_file_count` |
| Total Solidity measured | ~229 KB (~126 KB real, ~103 KB synthetic) | `aggregate.scan_file_total_bytes` |
| Full-corpus wall time | *pending Phase 3* | `aggregate.corpus_median_ns` (currently `null`) |

### Scope note on the README's `p99 < 10 ms` claim

The project [README's Performance section](../../README.md#performance) reports
the p99 bound over the **18 real fixtures only**. The three synthetic
fixtures (`synth-small` / `-medium` / `-large`) are excluded because
`synth-large` is a deliberately oversized 80 KB stress case with a p99 of
~50 ms — useful as a scaling probe, misleading as a headline. The cutoff
used is: if you include the synth samples, the worst real-fixture p99
(9.85 ms) and the worst synth p99 (50 ms) mix into a single statistic that
no real contract actually represents. The current `xtask perf` runner
writes p99 values per bench without filtering; the "< 10 ms" headline is
evaluated by skipping the three `synth-*` ids manually. Follow-up:
`xtask perf` could emit a separate `aggregate.real_fixtures_p99_ns` field
so the headline doesn't need an out-of-band filter.

## Per-fixture breakdown

All times are per-iteration (one full `scan_file_with` call). Throughput
shown in bytes is the fixture's Solidity size; Criterion reports
bytes/sec internally but the table below uses times for readability.

### Real contract fixtures (shipped under `core/src/contracts/`)

| Fixture | Size (B) | Median | p95 | p99 |
|---|---:|---:|---:|---:|
| `false-positive-edge-cases` | 2,839 | 2.08 ms | 2.34 ms | 2.74 ms |
| `cfg_true_positive` | 3,607 | 3.00 ms | 3.23 ms | 3.48 ms |
| `comprehensive-vulnerabilities` | 2,851 | 3.07 ms | 3.34 ms | 3.52 ms |
| `modern-staking-vault` | 3,493 | 3.54 ms | 4.33 ms | 4.93 ms |
| `new-detectors-test` | 4,821 | 3.54 ms | 4.06 ms | 4.95 ms |
| `production-yield-aggregator` | 6,021 | 3.57 ms | 4.08 ms | 4.32 ms |
| `production-staking-vault` | 6,474 | 3.69 ms | 4.07 ms | 4.49 ms |
| `defi-yield-aggregator` | 4,522 | 3.99 ms | 4.72 ms | 5.12 ms |
| `governance-timelock` | 6,051 | 4.03 ms | 4.42 ms | 4.54 ms |
| `cfg_false_positive_regression` | 6,068 | 4.03 ms | 5.53 ms | **9.85 ms** |
| `nft-staking-rewards` | 5,832 | 4.03 ms | 4.89 ms | 5.28 ms |
| `cross-chain-bridge` | 5,720 | 4.20 ms | 5.11 ms | 7.07 ms |
| `rewards-distributor` | 6,969 | 4.21 ms | 5.07 ms | 5.64 ms |
| `modern-liquidity-pool` | 6,234 | 4.37 ms | 5.25 ms | 6.29 ms |
| `production-erc20-staking` | 14,765 | 5.13 ms | 6.55 ms | 7.28 ms |
| `production-governance-token` | 10,260 | 5.78 ms | 6.66 ms | 7.36 ms |
| `test-patterns` | 10,696 | 6.08 ms | 7.49 ms | 9.63 ms |
| `production-token-vesting` | 18,304 | 6.47 ms | 7.49 ms | 7.73 ms |

**Median of medians:** 4.03 ms. **Max p99 (real):** 9.85 ms.

### Synthetic size-scaling fixtures (generated in-memory by the bench)

| Fixture | Size (B) | Median | p95 | p99 |
|---|---:|---:|---:|---:|
| `synth-small` | 2,524 | 1.12 ms | 1.28 ms | 1.43 ms |
| `synth-medium` | 20,084 | 8.74 ms | 9.98 ms | 12.17 ms |
| `synth-large` | 80,804 | 34.97 ms | 40.24 ms | 50.21 ms |

Synth fixtures exist so the bench produces a useful curve even if the
bundled real fixtures change. They also double as a quick scaling sanity
check: scan time is roughly linear in source bytes (~0.43 µs/byte at the
median on the reference machine that produced this run).

## Reproducing

```bash
# Full run, a few minutes, writes results/summary.json + Criterion HTML.
just bench-perf

# Quick smoke (single-shot per bench, ~30s; does not write summary.json).
cargo bench -p veil --bench scan_bench -- --quick

# Optional: wall-time comparator vs. Slither (requires Docker).
cargo xtask perf --compare slither
```

Absolute numbers depend on the host CPU/kernel. Only relative numbers
(median ratios, percentile spreads, regressions vs. `main`) are meaningful
across machines. The `bench.yml` workflow runs this on a fixed GitHub
Actions runner class so committed `summary.json` diffs are comparable
across PRs.

## When to update the committed `summary.json`

Only in the same PR as:

1. A detector change that the perf suite measurably reflects (i.e. the
   PR's CI bench run produces a non-noise diff vs. `main`).
2. A fixture add/remove under `core/src/contracts/` or a change to the
   synthetic-fixture generator in `core/benches/scan_bench.rs`.

Never hand-edit `results/*.json`.
