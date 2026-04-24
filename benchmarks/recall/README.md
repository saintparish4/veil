# Recall benchmark

Measures Veil's true-positive rate on a labeled vulnerability corpus.

## Corpus

- `swc/` -- curated SWC Registry subset (MIT), committed directly.
- `vendor/recall/smartbugs-curated/` -- fetched at pinned SHA via
  `just fetch`. Gitignored.
- (optional) `vendor/recall/smartbugs-wild/`,
  `vendor/recall/not-so-smart-contracts/` -- larger optional sources.

## Ground truth (`labels.yml`)

Each entry:

```yaml
- file: recall/swc/SWC-107-reentrancy/simple_dao.sol
  detector_id: reentrancy
  line: 19
  swc_id: SWC-107
  notes: Canonical DAO-style external call before state write.
```

Paths are relative to `benchmarks/`.

## Match rule

A finding matches a label iff:
- `finding.file == label.file` (corpus-relative, forward-slash)
- `finding.detector_id == label.detector_id`
- `|finding.line - label.line| <= 2`

## Reproduction

```
just fetch           # populates benchmarks/vendor/recall/ (SmartBugs, etc.)
just bench-recall    # runs cargo xtask recall; writes results/
```

## Outputs (all committed)

- `results/summary.md`   -- per-detector table + aggregate recall
- `results/summary.json` -- machine-readable for README consumption
- `results/misses.md`    -- labels with no matching finding (regressions)
- `results/extras.md`    -- findings on labeled files with no label (noise?)

## Built-in regression probe

`labels.yml` intentionally contains one label pointing at a non-existent
file (`recall/swc/does-not-exist/fake_file.sol`). This is **by design**: it
continuously exercises the runner's missing-file path so drift in that
code is caught the first time recall is run.

Consequences on every run:

- Headline recall reports **88.89%** (8 caught / 9 labeled) on the SWC
  corpus alone, not 100%. The "missing" label is the probe, not a real
  regression. Real detector regressions show up as *additional* misses.
- `misses.md` always lists the probe row.
- `summary.md` prints a blockquote warning about missing-on-disk labels.
- `recall_pct` in `summary.json` for the `reentrancy` detector reads
  50.00% for the same reason.

When evaluating real recall, subtract the probe: 8 / 8 across the SWC
fixtures. Remove the probe entry if you ever want a clean 100% headline
(e.g. for a README badge); the rest of the pipeline does not depend on it.

## Updating

1. Land a new detector or fix a miss -> `just bench-recall` -> commit the diff
   under `results/`.
2. Add new labels -> add entries to `labels.yml` -> re-run -> commit.
3. Bump a fetched corpus -> edit `corpus.toml` rev -> `just fetch --update` ->
   re-run -> commit.