// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-104: King of the Ether — unchecked .send() return value.
///         See SOURCE.md for attribution.
contract KingOfTheEther {
    address public king;
    uint256 public prize;

    constructor() {
        king = msg.sender;
    }

    function becomeKing() public payable {
        require(msg.value > prize, "not enough");

        address oldKing = king;
        king  = msg.sender;
        prize = msg.value;

        payable(oldKing).send(prize);
    }
}
