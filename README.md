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

- 13 source-level vulnerability detectors covering the OWASP Smart Contract Top 10
- Control flow graph (CFG) with taint propagation for reentrancy analysis
- Inter-procedural function summaries (intra-file storage-write and external-call propagation)
- EVM bytecode frontend (`veil evm`) — disassembly, EVM CFG, and source-map correlation for bugs invisible at the AST level
- Custom TOML rules in `.veil/rules/` — both pattern detectors and team-specific suppressions
- Plugin API (`veil-plugin`) for authoring custom detectors as Rust workspace members
- Audit diff mode (`veil diff`) — compare two scans for new vs. fixed findings with a risk delta
- SARIF 2.1.0 output compatible with GitHub Code Scanning
- JSON output for pipeline integration
- HTML and PDF security reports with custom branding
- Inline suppression comments (`// veil-ignore:`) and baseline files for CI
- Reusable GitHub Action (`veil-scan.yml`) for one-line CI gating
- Exit codes designed for CI gating (0 = clean, 1 = medium/low, 2 = high, 3 = critical)
- Recursive directory scanning

---

## Performance

Veil scans each Solidity fixture in a **median of ~4.0 ms** (p99 **< 10 ms**) across the 18 real contracts in the perf set (~126 KB Solidity), computed from [`benchmarks/perf/results/summary.json`](benchmarks/perf/results/summary.json). Reproduce:

```bash
make bench-perf
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
make bench-precision
cat benchmarks/precision/results/summary.md
```

The `make bench-precision` recipe auto-fetches the corpus on first run (shallow clones pinned to the resolved SHA) and is idempotent thereafter. `benchmarks/vendor/` stays gitignored; CI re-fetches each nightly run.

---

## Historical exploits

Veil flags the root-cause vulnerability in **12 of 14 reconstructed historical hacks** totalling **$1.63B of $1.84B** in losses (**88.5% coverage**). Each incident is a faithful minimum reconstruction from the verified on-chain source at the exploit block — not an SWC-style synthetic snippet — with ground truth pinned per-line in `expected.json` and a line-tolerance of ±2. Full headline in [`benchmarks/exploits/results/summary.md`](benchmarks/exploits/results/summary.md).

- **CAUGHT**: The DAO (2016, $60M) — reentrancy at line 24
- **CAUGHT**: King of the Ether Throne (2016, ~98 ETH silently dropped) — unchecked-calls at line 28
- **CAUGHT**: GovernMental Ponzi (2016, ~1,100 ETH stuck) — timestamp-dependence at line 26
- **MISSED (intended)**: Parity Multisig v1 (2017, $30M / 150k ETH) — detector roadmap
- **CAUGHT**: Parity Multisig v2 (2017, $150M / 513k ETH frozen) — access-control at line 21
- **CAUGHT**: SmartBillions Lottery (2017, ~$120k / 400 ETH) — unsafe-random at line 27
- **CAUGHT**: BEC Token batchOverflow (2018, ~$70M paper) — integer-overflow at line 26
- **CAUGHT**: bZx first flash-loan attack (2020, ~$350k) — flash-loan at line 25
- **CAUGHT**: Harvest Finance (2020, $24M) — flash-loan at line 25
- **CAUGHT**: Poly Network (2021, $611M returned) — access-control at line 23
- **MISSED (intended)**: Beanstalk Farms (2022, $182M) — detector roadmap
- **CAUGHT**: Nomad Bridge (2022, $190M) — unchecked-calls at line 29
- **CAUGHT**: Wormhole Bridge (2022, $325M) — access-control at line 22
- **CAUGHT**: Euler Finance (2023, $197M returned) — unchecked-calls at line 25

**Intended misses.** The two `MISSED` entries deliberately preserve the real contract shape. Renaming `stalk.balanceOf(voter)` to `token.balanceOf(voter)` would flip Beanstalk to CAUGHT, and rewriting Parity v1's `fallback() { walletLib.delegatecall(msg.data); }` as a textbook `forward(address, bytes)` function would flip Parity v1 — both changes misrepresent the scanner rather than measure it. Each miss is annotated `INTENDED MISS:` in its `expected.json` with the exact detector gate that skips the real-world shape and the fix proposal tracked for a follow-up detector PR. See [`benchmarks/exploits/README.md`](benchmarks/exploits/README.md#intended-misses--detector-roadmap) for the roadmap.

Reproduce:

```bash
make bench-exploits
cat benchmarks/exploits/results/summary.md
```

All four artifacts (`summary.md`, `summary.json`, `misses.md`, `extras.md`) are byte-deterministic across runs — the corpus and ground truth are committed in full under `benchmarks/exploits/<YYYY-slug>/`, and the bench never fetches or compiles anything at runtime.

---

## Installation

### Download a prebuilt binary (recommended)

Grab the archive for your platform from the [latest release](https://github.com/saintparish4/veil/releases/latest) — no Rust toolchain required. Binaries are published for Linux (x86_64, arm64), macOS (Intel, Apple Silicon), and Windows (x86_64), each with a SHA-256 checksum.

```bash
# Linux x86_64 example
curl -sSL https://github.com/saintparish4/veil/releases/latest/download/veil-x86_64-unknown-linux-gnu.tar.gz | tar xz
./veil --version
```

### Install with Cargo

```bash
# From the git repository (no crates.io publish required)
cargo install --git https://github.com/saintparish4/veil veil
```

Once Veil is published to crates.io you can also use [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall) to fetch the prebuilt binary directly:

```bash
cargo binstall veil
```

### Build from source

Requires Rust 1.75+ ([install](https://rustup.rs)).

```bash
git clone https://github.com/saintparish4/veil
cd veil
cargo build --release   # binary at target/release/veil
```

### Run without installing

```bash
cargo run -p veil -- scan <path>
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

# Analyse compiled EVM bytecode (bugs invisible at the AST level)
veil evm MyContract.bin --sourcemap MyContract.json --source contracts/MyContract.sol

# Diff two scans to gate CI on newly introduced findings
veil scan contracts/ -r --format json > after.json
veil diff before.json after.json
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
| `--no-rules` | Skip applying TOML rules from `.veil/rules/` |
| `-v, --verbose` | Enable debug logging to stderr |

### `veil evm <bytecode>`

Analyse compiled EVM bytecode for vulnerabilities that are invisible at the Solidity AST level (e.g. `DELEGATECALL` to a storage-loaded target, unprotected `SELFDESTRUCT`). Accepts a raw hex string (with or without `0x`) or a path to a `.bin`/hex file.

| Flag | Description |
|------|-------------|
| `<bytecode>` | Hex string (`0x…`) or path to a binary/hex file |
| `--sourcemap <FILE>` | solc source-map JSON for source correlation |
| `--source <FILE>` | Solidity source file for line-number resolution |
| `-f, --format <FORMAT>` | Output format: `terminal` (default) or `json` |

### `veil diff <before> <after>`

Compare two `veil scan --format json` outputs and report new vs. fixed findings. Findings are matched by identity (SHA-256 of `file:line:detector_id`). Exits `1` when new findings are introduced (subject to `--min-risk`), making it suitable for pull-request gating.

| Flag | Description |
|------|-------------|
| `<before>` | Baseline scan JSON |
| `<after>` | New scan JSON |
| `-f, --format <FORMAT>` | Output format: `json` (default) or `terminal` |
| `--min-risk <SCORE>` | Exit `1` only when new findings reach this risk score (`critical×100 + high×10 + medium×3 + low×1`) |

### Exit Codes

Designed for CI gating:

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Medium or low severity findings only |
| `2` | At least one high severity finding |
| `3` | At least one critical severity finding |

The repository also ships a reusable workflow that installs Veil, scans, gates on severity (or new-findings-only against a baseline), and uploads SARIF to Code Scanning:

```yaml
# .github/workflows/security.yml in your project
jobs:
  security:
    uses: saintparish4/veil/.github/workflows/veil-scan.yml@alpha
    with:
      path: contracts/
      severity-threshold: High
      fail-on-new-only: true
      baseline-path: .veil/baseline.json
```

Or wire the steps manually:

```yaml
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

### EVM bytecode detectors

`veil evm` runs a separate set of detectors over disassembled bytecode and the EVM CFG, catching issues that never appear in source — including compiler-introduced or proxy-deployed code:

| ID | Severity | What It Detects |
|----|----------|-----------------|
| `delegatecall-from-storage` | Critical | `DELEGATECALL` whose target address is loaded from storage (upgradeable-proxy hijack surface) |
| `unprotected-selfdestruct` | High | `SELFDESTRUCT` reachable without any preceding conditional guard |

With `--sourcemap`/`--source`, findings are correlated back to Solidity line numbers.

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

For pull-request gating, prefer `veil diff`, which compares two JSON scans by finding identity and can fail only when *new* findings cross a risk threshold:

```bash
veil scan contracts/ -r --format json > before.json   # on the base branch
veil scan contracts/ -r --format json > after.json    # on the PR branch
veil diff before.json after.json --min-risk 10        # exit 1 only on new High+ findings
```

---

## Custom Rules

Teams can add project-specific rules as TOML files under `.veil/rules/*.toml`. They are loaded automatically on every scan (disable with `--no-rules`) and applied after inline `// veil-ignore:` and baseline filtering. Two rule kinds are supported.

**Suppression rules** silence a known detector for a recognised pattern:

```toml
# .veil/rules/defi.toml
[[rules]]
detector = "reentrancy"
if_function_name_contains = "Callback"
reason = "Uniswap/Aave callbacks are invoked by verified pool contracts"
```

**Pattern rules** are custom detectors written as a predicate over each function:

```toml
[[rules]]
type = "pattern"
id = "custom-timelock"
severity = "High"
pattern = "function_name_contains('schedule') AND NOT has_modifier('onlyProposer')"
message = "Timelock schedule without proposer access control"
```

The predicate grammar supports `AND` / `OR` / `NOT`, parentheses, and the predicates `function_name_contains('…')`, `has_modifier('…')`, `body_contains('…')`, `is_external`, and `is_public`.

---

## Custom Detectors (Plugin API)

For logic beyond what TOML predicates express, author a detector in Rust against the `veil-plugin` crate and add it as a workspace member:

```toml
# Your project's Cargo.toml
[workspace.dependencies]
veil-plugin = { git = "https://github.com/saintparish4/veil" }
```

```rust
use veil_plugin::{AnalysisContext, Confidence, Detector, Finding, Severity};

pub struct MyDetector;

impl Detector for MyDetector {
    fn id(&self) -> &'static str { "my-custom-check" }
    fn name(&self) -> &'static str { "My Custom Check" }
    fn severity(&self) -> Severity { Severity::High }
    fn owasp_category(&self) -> Option<&'static str> { None }

    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        // walk ctx.functions / ctx.tree and push Finding values
    }
}
```

Detectors receive the same read-only `AnalysisContext` as the built-in detectors (parsed AST, source, function nodes, lazy CFG).

---

## Architecture

Veil is a Cargo workspace of four crates:

```
veil/
├── Cargo.toml               # Workspace: core, veil-evm, veil-plugin, xtask
├── core/                    # The `veil` library + CLI binary
│   └── src/
│       ├── main.rs              # CLI (clap): scan / evm / diff subcommands
│       ├── lib.rs               # Public API surface
│       ├── scan.rs              # Orchestration: parse → analyze → suppress → report
│       ├── detector_trait.rs    # Detector trait, AnalysisContext, DetectorRegistry
│       ├── ast_utils.rs         # Tree-sitter node helpers
│       ├── cfg.rs               # Control flow graph builder
│       ├── taint.rs             # Taint propagation over CFG
│       ├── interprocedural.rs   # Per-function summaries (intra-file may-analysis)
│       ├── defi_patterns.rs     # DeFi self-service / safe-pattern recognition
│       ├── storage_model.rs     # Proxy storage-layout modeling
│       ├── rule_engine.rs       # TOML pattern-rule predicate engine
│       ├── suppression_rules.rs # .veil/rules/ loading (suppression + pattern)
│       ├── suppression.rs       # Inline ignore parsing, baseline filtering
│       ├── diff.rs              # `veil diff` scan comparison + risk delta
│       ├── types.rs             # Finding, Severity, Confidence
│       ├── output.rs            # Terminal, JSON, SARIF formatters
│       ├── report.rs            # HTML/PDF report generation
│       └── detectors/           # 13 source-level detectors + build_registry
│           ├── mod.rs
│           ├── reentrancy.rs
│           └── … (12 more)
├── veil-evm/                # EVM bytecode frontend: disasm, EVM CFG, source maps
├── veil-plugin/             # Public API for authoring custom detectors
└── xtask/                   # Benchmark / repo automation runner
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
