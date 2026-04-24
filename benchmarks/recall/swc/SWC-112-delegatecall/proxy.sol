// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-112: delegatecall to a user-supplied address. See SOURCE.md.
contract Proxy {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SWC-112: attacker controls both `callee` and `data` — full takeover
    // of this contract's storage context (owner, balances, ...).
    function forward(address callee, bytes memory data) public {
        (bool ok, ) = callee.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
