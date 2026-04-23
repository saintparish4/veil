# Veil Benchmarks

This tree is the evidence base for every headline number cited in the
project [README](../README.md). Nothing here is hand-authored prose — each
result file is produced by a `cargo xtask` subcommand and committed so the
history of every claim is auditable from `git log`.

## Philosophy

1. **One command per claim.** Every bullet in the README's *Proof points*
   section ends with a `just …` invocation. If the command cannot be re-run
   to reproduce the number, the number does not belong in the README.
2. **Pinned inputs.** Large upstream corpora (OpenZeppelin, Uniswap, Aave,
   Compound, Curve, Lido, Maker, SmartBugs) are fetched at frozen commit
   SHAs declared in [`precision/corpus.toml`](precision/corpus.toml) into
   the gitignored `benchmarks/vendor/` tree. Small curated inputs (SWC
   subset, historical-exploit reconstructions, triage manifests) are
   committed directly so the repo is self-contained without running the
   fetch script.
3. **Same entry points as the CLI.** The runner (`xtask`) calls
   `veil::scan_file_with` and `veil::detectors::build_registry` — the
   exact functions the `veil` binary uses. No special benchmark-only code
   paths, no mocks.
4. **Windows-compatible.** Orchestration lives in Rust (`xtask`) rather
   than shell scripts, and the root `justfile` uses PowerShell on Windows.
   A contributor on any of the three major OSes runs `just bench` and gets
   the same artifacts.

## Layout

```
benchmarks/
├── README.md           ← you are here
├── precision/          ← false-positive rate on audited production code
│   ├── corpus.toml     ← pinned upstream SHAs
│   ├── triage/*.json   ← hand-triaged {finding_id → verdict, note}
│   └── results/        ← committed xtask output
├── recall/             ← true-positive rate on labeled vulnerability sets
│   ├── labels.yaml     ← ground truth
│   ├── swc/            ← vendored SWC Registry subset (MIT)
│   └── results/
├── exploits/           ← historical-incident reconstructions
│   └── <year>-<name>/  ← contract.sol, POSTMORTEM.md, expected.json
├── perf/               ← Criterion throughput + p50/p95/p99
│   └── results/
├── standards/          ← OWASP / SWC / SARIF conformance
│   ├── owasp-mapping.md
│   ├── swc-mapping.md
│   └── sarif-conformance.md
├── scripts/            ← thin wrappers that call `cargo xtask fetch`
└── vendor/             ← .gitignored, populated by `just fetch`
```

## Ground-truth format

### Precision triage (`precision/triage/<corpus>.json`)

```json
[
  {
    "id": "a1b2c3d4e5f6",
    "verdict": "real",
    "note": "Unbounded loop in LibraryRegistry.migrateAll — the comment at line 212 claims bounded iteration but the bound is attacker-controlled."
  },
  {
    "id": "0f1e2d3c4b5a",
    "verdict": "false-positive",
    "note": "Re-entrancy lint fires on an OZ v5 nonReentrant-guarded external call; safe by construction."
  }
]
```

The `id` is Veil's stable `Finding.id` (SHA-256 truncation computed in
[`core/src/types.rs`](../core/src/types.rs)'s `compute_id`). Any finding
ID appearing in the scan but not in the triage file causes
`xtask precision` to exit non-zero unless `--allow-untriaged` is passed.
This is what the README means by *"manually triaged."*

### Recall labels (`recall/labels.yaml`)

```yaml
- file: swc/SWC-107-reentrancy/Reentrancy.sol
  detector_id: reentrancy
  line: 19
  swc_id: SWC-107
  notes: Canonical classroom example; external call before state write.

- file: smartbugs-curated/access_control/proxy.sol
  detector_id: tx-origin
  line: 42
  swc_id: SWC-115
```

`xtask recall` matches a finding to a label when `file` and `detector_id`
are equal and `|finding.line − label.line| ≤ 2`.

### Exploit expectations (`exploits/<incident>/expected.json`)

```json
{
  "incident": "Nomad Bridge",
  "date": "2022-08-01",
  "loss_usd": 190_000_000,
  "expect": [
    { "detector_id": "unchecked-calls", "line": 124, "severity": "critical" }
  ]
}
```

A `POSTMORTEM.md` alongside `contract.sol` cites the original source
(Etherscan address, commit, or blog post) and summarises the loss.

## Reproduction

```bash
# One-time setup — fetch the pinned upstream corpora (~GB of Solidity).
just fetch

# Full pipeline, in dependency order.
just bench

# Individual suites.
just bench-perf        # Criterion + p50/p95/p99 summary
just bench-precision   # false-positive rate on audited production code
just bench-recall      # true-positive rate on labeled vulnerabilities
just bench-exploits    # historical-incident reconstructions
just bench-standards   # OWASP / SWC / SARIF conformance
just coverage          # line coverage via cargo-llvm-cov
```

All commands are idempotent. Result artifacts are re-written in place —
`git diff benchmarks/` is the regression report.

## When to update a number in the README

Exactly two times:

1. A detector lands, is deleted, or changes behaviour in a way the suite
   detects. The CI run on that PR will rewrite the affected
   `benchmarks/*/results/` files; commit the diff in the same PR.
2. A corpus is re-pinned to a new SHA in `precision/corpus.toml` or
   `recall/labels.yaml` gains new entries. Commit the result diff in the
   same PR as the corpus bump.

Never edit `benchmarks/*/results/` by hand.
