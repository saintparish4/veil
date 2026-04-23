# Precision corpus

Precision = `|findings triaged as real| / |findings triaged|`, measured
against a corpus of audited production DeFi source. The denominator
excludes findings still in `needs-triage` — those are blockers, not
signal.

## Inputs

`corpus.toml` pins eight upstream repositories to a tag or SHA. On first
`just fetch`, the script resolves each tag to an immutable SHA and writes
it to `benchmarks/vendor/precision/<name>/.veil-resolved-sha`. That SHA
is what the README cites.

## Workflow

1. `just fetch` (once, or after bumping a `rev` in corpus.toml).
2. `just bench-precision`. This:
   - scans every `.sol` file under `benchmarks/vendor/precision/` that
     matches the corpus's `include` globs and does not match its
     `exclude` globs;
   - groups findings by corpus and writes
     `results/<corpus>/findings.json` (raw output, sorted by `id`);
   - joins each finding against `triage/<corpus>.json` by `Finding.id`
     (the 16-hex-char stable ID from `core/src/types.rs::compute_id`);
   - writes `results/<corpus>/triage.md` with one row per finding,
     `results/summary.md` with per-corpus + aggregate precision %, and
     `results/summary.json` as the machine-readable twin.
3. Exit non-zero if any finding is `needs-triage` (pass
   `--allow-untriaged` to override during active triage work).
4. For every `needs-triage` finding, review the source and add an entry
   to `triage/<corpus>.json`. Commit triage updates in the same PR as
   the detector change that produced them.

## Ground truth

Only `real` / `false-positive` verdicts count. A `real` finding is one
a reasonable auditor would file against the upstream. A
`false-positive` is a finding the scanner emits that cannot be an
exploit given the upstream's guarantees (e.g. an `nonReentrant` modifier
already protects the call path Veil flags).

Re-triage is allowed: bumping a `rev`, a detector rewrite, or a line
shift can all change a `Finding.id`. The old entry becomes dead (no
matching finding this run) and a new entry is requested as
`needs-triage`. Dead entries are kept in the triage file for audit
history unless explicitly removed in the same PR as the triage update.

## Reproducing the README number

```
git clean -fdx benchmarks/vendor benchmarks/precision/results
just fetch
just bench-precision
cat benchmarks/precision/results/summary.md
```