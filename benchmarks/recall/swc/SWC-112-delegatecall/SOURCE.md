# SWC-112 — Delegatecall to Untrusted Callee

- SWC Registry entry: https://swcregistry.io/docs/SWC-112
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/delegatecall/proxy.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`forward(address callee, bytes memory data)` delegates execution to a
caller-controlled address with caller-controlled calldata. The callee
runs with this contract's storage, so it can overwrite `owner`, empty
any balances, or install new code paths.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`.
- Captured the low-level-call return value in `(bool ok, )` and
  `require(ok, ...)` so the fixture only trips SWC-112 (and not
  SWC-104 unchecked-calls on the same line).
- `function forward(...)` declaration sits on line 14; Veil reports at
  the function-declaration line. Label records 14 exactly.
