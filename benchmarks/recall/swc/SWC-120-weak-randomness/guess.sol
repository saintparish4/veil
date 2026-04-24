// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-120: weak RNG built from public block state. See SOURCE.md.
contract Guess {
    uint256 public secret;
    uint256 public lastBet;

    // SWC-120: keccak256(abi.encodePacked(block.timestamp, prevrandao, ...))
    // is cheaply gameable — the miner controls `block.timestamp` and
    // `block.prevrandao` in the same transaction that computes `secret`.
    function play() public payable returns (uint256) {
        require(msg.value == 1 ether, "bet 1 ether");
        lastBet = msg.value;
        secret = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender))
        );
        return secret;
    }
}
