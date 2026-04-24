// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice SWC-107 canonical reentrancy fixture. See SOURCE.md for attribution.
contract SimpleDAO {
    mapping(address => uint256) public credit;

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    function queryCredit(address to) public view returns (uint256) {
        return credit[to];
    }

    // SWC-107: external call precedes state change; no reentrancy guard.
    function withdraw(uint256 amount) public {
        require(credit[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        credit[msg.sender] -= amount;
    }
}
