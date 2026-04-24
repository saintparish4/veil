# SWC-104 — Unchecked Call Return Value

- SWC Registry entry: https://swcregistry.io/docs/SWC-104
- Upstream fixture : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/unchecked_return_value/KingOfTheEtherThrone.sol
- License          : MIT (see `../LICENSE-SWC-REGISTRY`)

## Vulnerability

`payable(oldKing).send(prize)` on line 21 silently ignores the boolean
return. If the deposed king is a contract whose `receive()` reverts,
their prize is lost-in-limbo — but `becomeKing()` still succeeds and
the caller crowns themselves anyway. Classic "King of the Ether" bug.

## Modifications from upstream

- Updated to `pragma solidity ^0.8.0`; the original predates `address
  payable` typing.
- Reordered so the unchecked `.send(...)` is the **last** statement
  in the function. This keeps the finding within ±2 lines of label
  line 21 regardless of whether Veil's CFG-taint path (reports at the
  sink/exit block) or the AST fallback (reports at the statement line)
  fires — both converge on lines 21–22 here.
- The crown/prize state writes happen *before* the send, so the
  reentrancy detector does not also fire on this fixture (keeps the
  labels file 1-to-1 with findings).
