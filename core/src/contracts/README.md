# Test Contract Fixtures

Solidity fixtures used by the scanner's tests and benchmarks. A few are wired
into specific tests via `include_str!` (see `detectors/mod.rs`, `main.rs`); the
rest form the throughput corpus that `core/benches/scan_bench.rs` globs over.

## Vulnerability patterns

| File | Purpose |
|------|---------|
| `test-patterns.sol` | Safe vs. vulnerable variants of all 7 vulnerability types, side by side. |
| `comprehensive-vulnerabilities.sol` | All 7 vulnerabilities in one contract — smoke test for every detector at once (`integration_scan_comprehensive_vulnerabilities`). |
| `new-detectors-test.sol` | Coverage for the newer detectors (flash loan, DoS loops, storage collision, unchecked ERC20, integer overflow, front-running). |

## Precision / false-positive regression

These should produce **few or zero** findings; they guard against false positives.

| File | Purpose |
|------|---------|
| `false-positive-edge-cases.sol` | Safe patterns historically misflagged by heuristics. |
| `cfg_false_positive_regression.sol` | CFG-based reentrancy: safe flow that must not be flagged. |
| `cfg_true_positive.sol` | CFG-based reentrancy: genuine finding that must still fire. |

## Modern DeFi (heuristic coverage)

Exercise the self-service and visibility-aware reentrancy heuristics. Each mixes
intentional vulnerabilities with safe code; see the header comment in each file.

- `modern-staking-vault.sol`
- `defi-yield-aggregator.sol`
- `nft-staking-rewards.sol`
- `modern-liquidity-pool.sol`
- `governance-timelock.sol`
- `rewards-distributor.sol`
- `cross-chain-bridge.sol`

## Production-grade (should scan clean)

Realistic implementations intended to pass with zero warnings. Documented in
detail in [`PRODUCTION-CONTRACTS.md`](./PRODUCTION-CONTRACTS.md).

- `production-erc20-staking.sol`
- `production-governance-token.sol`
- `production-staking-vault.sol`
- `production-token-vesting.sol`
- `production-yield-aggregator.sol`

## Running scans

```bash
# Scan the whole fixture directory
cargo run -- scan core/src/contracts/ --recursive

# A single fixture, JSON output
cargo run -- scan core/src/contracts/test-patterns.sol --format json
```
