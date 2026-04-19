// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Contract with patterns that trigger false positives in string-matching
/// detectors. Each function isolates one FP scenario. Safe code only —
/// no real vulnerabilities.
///
/// S1.5c: tests assert these FPs EXIST (documenting current behavior).
/// S2:    tests flip to assert ZERO FPs after AST-based rewrite.
contract FalsePositiveEdgeCases {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------
    // FP 1: `.call` mentioned in a comment (not actual code)
    // String-matching detectors see ".call{" and flag reentrancy.
    // ---------------------------------------------------------------
    function safeFunction() external view returns (uint256) {
        // Docs: user.call{value: 1}("") is the low-level call pattern
        return balances[msg.sender];
    }

    // ---------------------------------------------------------------
    // FP 2: `.call` inside a string literal
    // ---------------------------------------------------------------
    function getCallSignature() external pure returns (string memory) {
        string memory s = "addr.call{value: x}()";
        return s;
    }

    // ---------------------------------------------------------------
    // FP 3: `tx.origin` in a comment
    // ---------------------------------------------------------------
    function safeSenderCheck() external view returns (bool) {
        // Note: we intentionally avoid tx.origin here for security
        return msg.sender == owner;
    }

    // ---------------------------------------------------------------
    // FP 4: `delegatecall` in an event name
    // ---------------------------------------------------------------
    event DelegatecallExecuted(address indexed target, bool success);

    function emitEvent() external {
        emit DelegatecallExecuted(address(this), true);
    }

    // ---------------------------------------------------------------
    // FP 5: `block.timestamp` in a string literal
    // ---------------------------------------------------------------
    function getTimestampDoc() external pure returns (string memory) {
        return "block.timestamp == deadline is dangerous";
    }

    // ---------------------------------------------------------------
    // FP 6: `require` in a comment that looks like access control
    // ---------------------------------------------------------------
    function openAction() external {
        // require(msg.sender == owner) was removed intentionally
        // This function is meant to be open to all
        balances[msg.sender] += 1;
    }
}
