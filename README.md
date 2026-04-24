# Veil [UNDER CONSTRUCTION]

**Accurate smart contract security analysis for modern DeFi.**

Veil is a static analysis scanner for Solidity smart contracts that solves the false-positive problem plaguing traditional security tools. Most scanners flag legitimate DeFi patterns — user withdrawals, staking claims, reward distributions — as vulnerabilities, burying real issues under noise. Veil understands modern smart contract architecture and delivers precise, actionable findings.

---

## Why Veil

Traditional scanners treat every external call as a reentrancy risk, every `withdraw` function as missing access control, and every `block.timestamp` usage as dangerous. The result is dozens of false positives per contract, eroding trust in automated tooling and forcing teams to ignore warnings entirely.

Veil is built differently:

- **Self-service awareness** — `stake()`, `unstake()`, `claimRewards()`, `withdraw()` operating on `msg.sender` are correctly identified as safe user-initiated functions, not access control gaps.
- **Visibility-aware severity** — reentrancy risk in a `private` helper is fundamentally different from risk in an `external` function. Veil adjusts severity accordingly.
- **CFG-based analysis** — reentrancy and unchecked-call detectors use a real control flow graph rather than heuristic line ordering. State writes that provably precede external calls do not trigger.
- **AST-only detection** — no string matching on raw source text. Every detector operates on the tree-sitter parse tree, eliminating spurious matches inside comments, string literals, and multi-line expressions.

---

## Features

- 13 vulnerability detectors covering the OWASP Smart Contract Top 10
- Control flow graph (CFG) with taint propagation for reentrancy analysis
- SARIF 2.1.0 output compatible with GitHub Code Scanning
- JSON output for pipeline integration
- HTML and PDF security reports with custom branding
- Inline suppression comments (`// veil-ignore:`)
- Baseline files to silence known findings in CI
- Exit codes designed for CI gating (0 = clean, 1 = medium/low, 2 = high, 3 = critical)
- Recursive directory scanning

---

## Performance

Veil scans each Solidity fixture in a **median of ~4.0 ms** (p99 **< 10 ms**) across the 18 real contracts in the perf set (~126 KB Solidity), computed from [`benchmarks/perf/results/summary.json`](benchmarks/perf/results/summary.json). Reproduce:

```bash
just bench-perf
```

Numbers come from Criterion's `scan_file/*` group driven through `veil::scan::scan_file_with` — the same entry point the `veil` binary uses. Three synthetic fixtures (`synth-small`/`medium`/`large`, up to 80 KB) are excluded from the headline p99 since `synth-large` is deliberately oversized for scaling studies; see [`benchmarks/perf/README.md`](benchmarks/perf/README.md) for the full per-fixture breakdown.

---

## Precision

Veil is measured against a corpus of **526 Solidity files (~20.4k LOC)** across **eight audited production-DeFi repositories**, each pinned to an immutable commit SHA resolved from its upstream release tag:

| Corpus | Rev | Files |
|--------|-----|------:|
| [openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | `v5.0.2` | 142 |
| [lido-core](https://github.com/lidofinance/core) | `v2.2.0` | 75 |
| [aave-v3-core](https://github.com/aave/aave-v3-core) | `v1.19.3` | 77 |
| [balancer-v2-vault](https://github.com/balancer/balancer-v2-monorepo) | `vault-deployment` | 68 |
| [compound-v3-comet](https://github.com/compound-finance/comet) | `audit/oz/original-weth-proposal` | 63 |
| [uniswap-v3-periphery](https://github.com/Uniswap/v3-periphery) | `v1.3.0` | 52 |
| [uniswap-v3-core](https://github.com/Uniswap/v3-core) | `v1.0.0` | 33 |
| [makerdao-dss](https://github.com/makerdao/dss) | `master` | 16 |
| **Total** | — | **526** |

Resolved SHAs are recorded per-corpus at `benchmarks/vendor/precision/<name>/.veil-resolved-sha` for the audit trail; the canonical `rev` list lives in [`benchmarks/precision/corpus.toml`](benchmarks/precision/corpus.toml).

**Methodology.** Precision = `real / (real + false_positive)`, measured over every finding Veil emits on the corpus. Findings awaiting triage do not contribute to either numerator or denominator and cause CI to fail unless `--allow-untriaged` is passed — i.e. "unclassified" is never silently counted as either signal or noise. Ground-truth verdicts follow the rules in [`benchmarks/precision/README.md`](benchmarks/precision/README.md).

**Current status.** The corpus is vendored and the scanner emitted **404 findings** across 526 files on the pinned SHAs (see [`benchmarks/precision/results/summary.json`](benchmarks/precision/results/summary.json) and [`summary.md`](benchmarks/precision/results/summary.md)). Triage is in progress; the aggregate precision percentage will be published here once every finding has a `real` / `false-positive` verdict committed under `benchmarks/precision/triage/`.

Reproduce:

```bash
just bench-precision
cat benchmarks/precision/results/summary.md
```

The `just bench-precision` recipe auto-fetches the corpus on first run (shallow clones pinned to the resolved SHA) and is idempotent thereafter. `benchmarks/vendor/` stays gitignored; CI re-fetches each nightly run.

---

## Installation

### Prerequisites

- Rust 1.75+ ([install](https://rustup.rs))

### Build from source

```bash
git clone https://github.com/saintparish4/veil
cd veil
cargo build --release
```

The `veil` binary will be at `target/release/veil`.

### Run without installing

```bash
cargo run --features cli -- scan <path>
```

---

## Quick Start

```bash
# Scan a single file
veil scan MyContract.sol

# Scan an entire project
veil scan contracts/ --recursive

# Output JSON for pipeline consumption
veil scan contracts/ --recursive --format json > findings.json

# Generate a SARIF report for GitHub Code Scanning
veil scan contracts/ --recursive --format sarif > results.sarif

# Generate an HTML security report
veil scan contracts/ --recursive --report html > report.html
```

---

## CLI Reference

### `veil scan <path>`

Scan a `.sol` file or directory.

| Flag | Description |
|------|-------------|
| `<path>` | File or directory to scan |
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, `sarif` |
| `-r, --recursive` | Walk subdirectories (directory scan only) |
| `--baseline <FILE>` | Suppress findings present in a JSON baseline file |
| `--report <FORMAT>` | Generate a report: `html` or `pdf` (written to stdout) |
| `--logo <PATH>` | Logo image path for reports |
| `--org-name <NAME>` | Organization name for report header |
| `-v, --verbose` | Enable debug logging to stderr |

### Exit Codes

Designed for CI gating:

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Medium or low severity findings only |
| `2` | At least one high severity finding |
| `3` | At least one critical severity finding |

```yaml
# GitHub Actions example
- name: Scan contracts
  run: veil scan contracts/ --recursive --format sarif > results.sarif
  
- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Output Formats

### Terminal (default)

Color-coded findings grouped by severity with fix suggestions and a summary table.

```
[CRITICAL] Dangerous Delegatecall — Proxy.sol:42
  User-controlled address passed to delegatecall without access control.
  Fix: Restrict delegatecall targets to a known implementation address.

[HIGH] Reentrancy — Vault.sol:87
  External call precedes state write: balances[msg.sender] updated after call.
  Fix: Apply checks-effects-interactions or add a nonReentrant modifier.

── Summary ──────────────────────────
  Critical  1    High  3    Medium  2    Low  0
```

### JSON

```json
{
  "findings": [
    {
      "id": "a3f82c1d",
      "detector_id": "reentrancy",
      "severity": "High",
      "confidence": "High",
      "line": 87,
      "vulnerability_type": "Reentrancy",
      "message": "External call precedes state write...",
      "suggestion": "Apply checks-effects-interactions...",
      "owasp_category": "SC01:2025 - Reentrancy",
      "file": "Vault.sol"
    }
  ],
  "statistics": {
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 0
  }
}
```

### SARIF

Full SARIF 2.1.0 output with rule definitions, severity levels, and physical locations. Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-aware tooling.

### HTML / PDF

Executive-style security reports with findings table, severity breakdown, remediation guidance, and optional organizational branding. PDF generation requires `wkhtmltopdf` or headless Chrome.

```bash
veil scan contracts/ --recursive --report html --org-name "Acme Protocol" --logo logo.png > report.html
```

---

## Detectors

Veil ships 13 detectors mapped to the OWASP Smart Contract Top 10 (2025).

| ID | Severity | What It Detects |
|----|----------|-----------------|
| `reentrancy` | High | External calls that precede state writes; CFG taint analysis with CEI-pattern awareness and reentrancy guard recognition |
| `unchecked-calls` | Medium | `.call`, `.transfer`, `.send` return values not checked on any path to function exit |
| `tx-origin` | High | `tx.origin` used in equality or inequality expressions for authentication |
| `access-control` | High | Sensitive operations (ownership transfer, fund movement, upgrades) without `onlyOwner`/`msg.sender` guards; distinguishes admin functions from self-service user actions |
| `dangerous-delegatecall` | Critical | `delegatecall` to a user-supplied or unvalidated address without access control |
| `timestamp-dependence` | Medium / High | `block.timestamp` in exact equality checks (Medium) or modulo expressions (High) |
| `unsafe-randomness` | High | On-chain randomness derived from `blockhash`, `block.prevrandao`, or `keccak256(abi.encodePacked(...))` with block-based inputs |
| `integer-overflow` | High | Arithmetic inside `unchecked {}` blocks; contracts on Solidity `<0.8.0` without overflow protection |
| `flash-loan` | High | Flash loan callback names, price manipulation patterns, and unvalidated callback callers |
| `storage-collision` | Critical / High | Proxy/upgradeable contracts missing `__gap` storage padding, unprotected initializers, constructors in proxy implementations, non-standard storage slots |
| `front-running` | Medium | ERC20 approval race conditions, missing slippage parameters on swaps, front-runnable auctions, mint/liquidation MEV exposure |
| `dos-loops` | Medium / High | External calls inside loops, unbounded iteration over dynamic arrays, growing-array patterns, expensive per-iteration operations |
| `unchecked-erc20` | High | `transfer`, `transferFrom`, and `approve` return values not checked (targets non-reverting ERC20s like USDT) |

### What Veil Does Not Flag

Veil is tuned not to produce findings on these correct patterns:

- `withdraw()`, `unstake()`, `claimRewards()` operating exclusively on `msg.sender` state
- `nonReentrant` or Checks-Effects-Interactions patterns in reentrancy analysis
- `block.timestamp >= startTime + duration` range comparisons (timestamp dependence)
- `internal` and `private` functions in visibility-adjusted reentrancy scoring
- ERC-4626 `deposit`/`redeem` patterns with share-based accounting

---

## Suppression

### Inline comments

Suppress a finding on the next line:

```solidity
// veil-ignore: reentrancy
(bool ok,) = recipient.call{value: amount}("");
```

Suppress by vulnerability type on a specific line:

```solidity
// veil-ignore: timestamp-dependence L142
```

Suppress all findings on the next line:

```solidity
// veil-ignore:
someRiskyCall();
```

### Baseline files

Generate a baseline to silence all current findings in CI, then track only new ones:

```bash
# Create baseline from current findings
veil scan contracts/ --recursive --format json | jq '.findings' > baseline.json

# Future runs — only new findings appear
veil scan contracts/ --recursive --baseline baseline.json
```

Baseline matching is normalized: finding `(file, line, vulnerability_type)` tuples are compared case-insensitively with hyphens and underscores treated as equivalent.

---

## Architecture

```
veil/
├── Cargo.toml
└── core/
    └── src/
        ├── main.rs              # CLI (clap), integration tests
        ├── lib.rs               # Public API surface
        ├── scan.rs              # Orchestration: parse → analyze → suppress → report
        ├── detector_trait.rs    # Detector trait, AnalysisContext, DetectorRegistry
        ├── ast_utils.rs         # Tree-sitter node helpers
        ├── cfg.rs               # Control flow graph builder
        ├── taint.rs             # Taint propagation over CFG
        ├── types.rs             # Finding, Severity, Confidence
        ├── output.rs            # Terminal, JSON, SARIF formatters
        ├── report.rs            # HTML/PDF report generation
        ├── suppression.rs       # Inline ignore parsing, baseline filtering
        └── detectors/
            ├── mod.rs           # Registry (build_registry)
            ├── reentrancy.rs
            ├── unchecked_calls.rs
            ├── tx_origin.rs
            ├── access_control.rs
            ├── delegatecall.rs
            ├── timestamp.rs
            ├── unsafe_random.rs
            ├── integer_overflow.rs
            ├── flash_loan.rs
            ├── storage_collision.rs
            ├── front_running.rs
            ├── dos_loops.rs
            └── unchecked_erc20.rs
```

Each detector is a zero-sized struct implementing the `Detector` trait. Detectors receive a read-only `AnalysisContext` containing the parsed tree-sitter AST, raw source, pre-computed function nodes, and a lazy CFG cache. They append `Finding` values without side effects.

See [`core/src/detectors/README.md`](core/src/detectors/README.md) for the full detector development guide, including how to add a new detector, write false-positive regression tests, and use the AST utility reference.

---

## Development

### Run tests

```bash
cargo test
```

### Run a scan against test fixtures

```bash
# Scan all test contracts
cargo run -- scan core/src/contracts/ --recursive

# Verify zero false positives on production-quality contracts
cargo run -- scan core/src/contracts/production-erc20-staking.sol

# Test visibility-aware reentrancy scoring
cargo run -- scan core/src/contracts/cross-chain-bridge.sol
```

### Snapshot tests

CFG structure is snapshot-tested with `insta`. To review and accept updated snapshots:

```bash
cargo test
cargo insta review
```

---

## Technology

| Component | Crate |
|-----------|-------|
| Solidity parsing | `tree-sitter` + `tree-sitter-solidity` |
| CLI | `clap` 4 (derive) |
| Serialization | `serde` + `serde_json` |
| Directory walking | `walkdir` |
| Fingerprinting | `sha2` |
| Terminal output | `colored` |
| Logging | `tracing` |

---

## License

MIT © Sharif Parish
