# SWC-107 — Reentrancy

- SWC Registry entry: https://swcregistry.io/docs/SWC-107
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/reentrancy/simple_dao.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

Classic DAO-style reentrancy. `withdraw` performs an external
`msg.sender.call{value: amount}("")` *before* decrementing the user's
credit, so a malicious `receive()` / `fallback()` can re-enter `withdraw`
and drain the balance.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0` and the modern low-level-call
  pattern (`(bool ok, ) = msg.sender.call{value: amount}("")`) so the
  fixture parses cleanly with tree-sitter-solidity 1.2.x.
- Added SPDX header.
- Kept line 19 as the external call — `benchmarks/recall/labels.yml`
  references that line with a ±2 match window.
