# SWC-128 — DoS with Block Gas Limit

- SWC Registry entry: https://swcregistry.io/docs/SWC-128
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/denial_of_service/list_dos.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`distribute()` iterates `recipients` (populated by the external
`register()` — attacker-controlled length) and performs a `.transfer`
inside the loop. An attacker can register thousands of addresses, or
a single contract whose `receive()` reverts, and brick the entire
distribution.

This fixture doubles as a regression for two Veil `dos-loops` patterns:

1. *Unbounded Loop* — `i < recipients.length` with no `limit`/
   `MAX_*`/`batchSize` sentinel.
2. *External Call in Loop* — `.transfer(...)` inside the body.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`.
- Added the `register()` helper so the `recipients` array is
  attacker-controlled rather than set in the constructor — makes the
  "push-over-pull antipattern" reason obvious in the postmortem.
- `function distribute()` declaration sits on line 18; label records
  line 18 exactly. Veil's `dos-loops` detector reports at the
  function-declaration line for all its sub-patterns.
