// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-115: tx.origin used for authorization — phishable.
///         See SOURCE.md for attribution.
contract Phishable {
    address public owner;

    constructor() { owner = msg.sender; }

    function withdrawAll(address payable _recipient) public {
        // SWC-115: tx.origin is the EOA that initiated the transaction,
        require(tx.origin == owner, "not owner");
        _recipient.transfer(address(this).balance);
    }
}
