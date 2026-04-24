# SWC-120 — Weak Sources of Randomness from Chain Attributes

- SWC Registry entry: https://swcregistry.io/docs/SWC-120
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/weak_sources_of_randomness/guess_the_random_number.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`secret = uint256(keccak256(abi.encodePacked(block.timestamp,
block.prevrandao, msg.sender)))` uses only publicly-observable or
miner-controlled values, so any account (especially a miner or
validator) can compute `secret` in the same block and win the bet.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0` and replaced the post-merge-
  deprecated `block.difficulty` with its successor `block.prevrandao`.
- Added a second state variable (`lastBet`) and a `require(msg.value
  == 1 ether)` precondition so the function is externally-callable
  and non-view, which is what Veil's `unsafe-random` detector looks for.
- `function play()` lands on line 12; label records line 11, inside
  the ±2 window around the function-declaration line.
