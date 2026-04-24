// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-116: block.timestamp used as time proxy + entropy in a
///         betting game. Miners can bias it within ~15s. See SOURCE.md.
contract Roulette {
    uint256 public pastBlockTime;

    constructor() payable {}

    function stash() external payable {
        pastBlockTime = block.timestamp;
    }

    // SWC-116: winners determined by `(block.timestamp % 15) == 0` —
    // miners choose a timestamp within a ~15-second window, so the
    // "randomness" is fully manipulable for them.
    function spin() public payable {
        require(msg.value == 10 ether, "bet must be 10 ether");
        require(block.timestamp != pastBlockTime, "one spin per block");
        pastBlockTime = block.timestamp;
        if (block.timestamp % 15 == 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
