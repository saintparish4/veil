// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-128: DoS via unbounded loop with external calls.
///         See SOURCE.md for attribution.
contract Distribute {
    address payable[] public recipients;

    function register() external {
        recipients.push(payable(msg.sender));
    }

    // SWC-128: loop over an attacker-controlled array with an external
    // call inside. A single recipient whose `receive()` reverts DoS's
    // the entire function for every caller forever — classic push-over-
    // pull antipattern; users can never claim their share.
    //
    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].transfer(address(this).balance / recipients.length);
        }
    }
}
