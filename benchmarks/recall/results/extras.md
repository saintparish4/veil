# Recall -- extras (findings on labeled files without a matching label)

These findings land on labeled files but no label within ±2 lines of them. They are either legitimate extra catches (add them to labels.yml) or noise (cross-check with precision triage).

| File | Line | Detector | Severity |
|------|-----:|----------|----------|
| `recall/swc/SWC-112-delegatecall/proxy.sol` | 14 | access-control | HIGH |
| `recall/swc/SWC-115-tx-origin/tx_origin.sol` | 14 | unchecked-calls | MEDIUM |
| `recall/swc/SWC-115-tx-origin/tx_origin.sol` | 11 | access-control | HIGH |
| `recall/swc/SWC-115-tx-origin/tx_origin.sol` | 14 | unchecked-erc20 | HIGH |
| `recall/swc/SWC-116-timestamp/roulette.sol` | 23 | unchecked-calls | MEDIUM |
| `recall/swc/SWC-128-dos-gas-limit/distribute.sol` | 20 | unchecked-calls | MEDIUM |
| `recall/swc/SWC-128-dos-gas-limit/distribute.sol` | 9 | dos-loops | MEDIUM |
| `recall/swc/SWC-128-dos-gas-limit/distribute.sol` | 20 | unchecked-erc20 | HIGH |
