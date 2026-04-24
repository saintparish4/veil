# SWC-106 — Unprotected SELFDESTRUCT Instruction

- SWC Registry entry: https://swcregistry.io/docs/SWC-106
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/unprotected_selfdestruct/mortal.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`kill()` is externally callable and invokes `selfdestruct` with no access
control. Any account can destroy the contract and redirect its ether to
themselves.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`.
- Added an explicit `receive()` so the contract can hold ether, making
  the selfdestruct impact meaningful.
- Added a 1-line SWC comment directly above the `function kill()`
  declaration to document the missing guard.
- `function kill()` lands on line 10 — label records line 9, inside the
  ±2 window.

## Why the access-control detector fires here

Veil's `access-control` detector flags externally-callable functions
that (a) are not in the whitelist of pure-user operations (`deposit`,
`stake`, `balanceOf`, ...), (b) perform a privileged operation like
`selfdestruct`, and (c) have no `onlyOwner`-style modifier or
`msg.sender` comparison. All three hold here.
