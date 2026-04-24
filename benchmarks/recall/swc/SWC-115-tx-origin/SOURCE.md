# SWC-115 — Authorization through tx.origin

- SWC Registry entry: https://swcregistry.io/docs/SWC-115
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/authorization_through_tx_origin/tx_origin.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`require(tx.origin == owner, ...)` lets any contract the owner has been
phished into calling drain the balance, because `tx.origin` is the EOA
that signed the *outer* transaction, not the direct caller.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`.
- Renamed `sendTo` -> `withdrawAll` for clarity; behaviour unchanged.
- The `require(tx.origin == owner, ...)` sits on line 13 — labels file
  records line 12 and the ±2 match window covers the binary expression.
