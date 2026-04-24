# Veil recall — SWC Registry subset

Minimal, hand-curated Solidity fixtures drawn from the
[SWC Registry](https://github.com/SmartContractSecurity/SWC-registry) (MIT).
Each sub-directory corresponds to one SWC ID and contains:

- `<fixture>.sol` — the minimal reproduction. Line numbers are stable and
  must be kept in sync with `benchmarks/recall/labels.yml`.
- `SOURCE.md` — upstream URL + commit SHA the fixture was adapted from,
  short description, and any modifications.

The SWC Registry itself is MIT-licensed; see
[`LICENSE-SWC-REGISTRY`](LICENSE-SWC-REGISTRY) for the full text.

## Layout

```
swc/
├── README.md                          ← you are here
├── LICENSE-SWC-REGISTRY               ← MIT attribution
├── SWC-104-unchecked-call/king.sol
├── SWC-106-selfdestruct/mortal.sol
├── SWC-107-reentrancy/simple_dao.sol
├── SWC-112-delegatecall/proxy.sol
├── SWC-115-tx-origin/tx_origin.sol
├── SWC-116-timestamp/roulette.sol
├── SWC-120-weak-randomness/guess.sol
└── SWC-128-dos-gas-limit/distribute.sol
```

## Editing rules

1. **Never renumber lines casually.** `labels.yml` references exact line
   numbers in these files; match tolerance is ±2. Shifting the vulnerable
   expression by more than 2 lines silently breaks the recall bench.
2. **Keep fixtures minimal.** One contract, one vulnerability. Nothing
   else. Noise here contaminates the `extras.md` false-positive stream.
3. **One SWC per directory.** Mixing categories makes the per-detector
   recall table meaningless.
4. **SPDX header required.** `// SPDX-License-Identifier: MIT` on line 1;
   everything here is MIT.

## Adding a new fixture

1. Pick an SWC ID from https://swcregistry.io.
2. Create `SWC-<id>-<short-name>/<fixture>.sol` with the minimal repro.
3. Add a `SOURCE.md` citing the upstream file + commit SHA.
4. Add the detector → SWC mapping to `benchmarks/standards/swc-mapping.md`.
5. Add a label entry to `benchmarks/recall/labels.yml` with the exact
   line number of the vulnerable expression.
6. Run `cargo xtask recall --no-auto-fetch` and confirm it appears as a
   caught label (not a miss, not an extra).
