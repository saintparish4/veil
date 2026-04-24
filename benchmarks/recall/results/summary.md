# Recall summary

- labeled sites: **9**
- caught: **8**
- missed: **1**
- recall: **88.89%**
- scanned files: 8
- extras (finding w/o label on labeled files): 8

> 1 labeled file(s) missing on disk -- counted as misses. Fix labels.yml or fetch the corpus.

## Per-detector

| Detector | Expected | Caught | Missed | Recall |
|----------|---------:|-------:|-------:|-------:|
| access-control | 1 | 1 | 0 | 100.00% |
| dangerous-delegatecall | 1 | 1 | 0 | 100.00% |
| dos-loops | 1 | 1 | 0 | 100.00% |
| reentrancy | 2 | 1 | 1 | 50.00% |
| timestamp-dependence | 1 | 1 | 0 | 100.00% |
| tx-origin | 1 | 1 | 0 | 100.00% |
| unchecked-calls | 1 | 1 | 0 | 100.00% |
| unsafe-random | 1 | 1 | 0 | 100.00% |

Recall = caught / expected. Match window is ±2 lines. See `misses.md` for labels with no matching finding and `extras.md` for findings on labeled files that no label explains (candidate noise).
