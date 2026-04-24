// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-106: Unprotected SELFDESTRUCT — anyone can call kill().
///         See SOURCE.md for attribution.
contract Mortal {
    receive() external payable {}

    // SWC-106: no onlyOwner / msg.sender check — anyone can kill the
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
