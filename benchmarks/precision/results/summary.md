# Precision summary

| Corpus | Rev | Files | Findings | Real | FP | Needs-triage | Precision |
|--------|-----|------:|---------:|-----:|---:|-------------:|----------:|
| openzeppelin-contracts | `v5.0.2` | 142 | 59 | 0 | 0 | 59 | — |
| uniswap-v3-core | `v1.0.0` | 33 | 23 | 0 | 0 | 23 | — |
| uniswap-v3-periphery | `v1.3.0` | 52 | 42 | 0 | 0 | 42 | — |
| aave-v3-core | `v1.19.3` | 77 | 37 | 0 | 0 | 37 | — |
| compound-v3-comet | `audit/oz/original-weth-proposal` | 63 | 49 | 0 | 0 | 49 | — |
| balancer-v2-vault | `vault-deployment` | 68 | 69 | 0 | 0 | 69 | — |
| lido-core | `v2.2.0` | 75 | 109 | 0 | 0 | 109 | — |
| makerdao-dss | `master` | 16 | 16 | 0 | 0 | 16 | — |
| **aggregate** | — | **526** | **404** | **0** | **0** | **404** | **—** |

Precision = real / (real + false-positive). `needs-triage` findings are blockers: they do not contribute to either numerator or denominator and cause CI to fail unless `--allow-untriaged` is passed.
