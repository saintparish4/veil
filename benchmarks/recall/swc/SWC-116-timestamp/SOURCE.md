# SWC-116 — Block values as a proxy for time

- SWC Registry entry: https://swcregistry.io/docs/SWC-116
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/time_manipulation/roulette.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`spin()` uses `block.timestamp % 15 == 0` as both the game's timing
source and its randomness source. Miners/validators can bias
`block.timestamp` within the ~15-second network-drift window and win
every time.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`.
- Added a second helper function (`stash`) purely to make the
  single-function Roulette parse cleanly and to keep the vulnerable
  `spin()` function on line 18 — label records line 17, inside the
  ±2 window around the function-declaration line Veil reports at.
- The `block.timestamp % 15 == 0` expression is the trigger for both
  `has_modulo` and `has_equality` branches in the detector.
