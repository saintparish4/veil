// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Comprehensive Vulnerabilities - All 7 vulnerability types in one contract
/// Perfect for quick smoke testing - should detect all vulnerability types
contract ComprehensiveVulnerabilities {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public prize;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
    }

    // VULNERABILITY 1: Reentrancy (state change after external call)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount; // State change AFTER external call
    }

    // VULNERABILITY 2: Unchecked external call
    function forwardFunds(address payable recipient) public {
        // Intentionally not checking return value - vulnerability for testing
        (bool success, ) = recipient.call{value: address(this).balance}("");
        success; // Suppress unused variable warning
    }

    // VULNERABILITY 3: tx.origin authentication
    function emergencyWithdraw() public {
        require(tx.origin == owner); // Using tx.origin instead of msg.sender
        (bool success, ) = payable(owner).call{value: address(this).balance}("");
        require(success);
    }

    // VULNERABILITY 4: Missing access control
    function withdrawAll(address payable to) public {
        // No access control - anyone can drain the contract!
        (bool success, ) = to.call{value: address(this).balance}("");
        require(success);
    }

    // VULNERABILITY 5: Dangerous delegatecall
    function execute(address target, bytes memory data) public {
        // Intentionally not checking return value - vulnerability for testing
        (bool success, ) = target.delegatecall(data);
        success; // Suppress unused variable warning
    }

    // VULNERABILITY 6: Timestamp dependence
    function claimPrize() public {
        require(block.timestamp % 15 == 0, "Not the right time"); // Exact timestamp check
        (bool success, ) = payable(msg.sender).call{value: prize}("");
        require(success);
    }

    // VULNERABILITY 7: Unsafe randomness
    function lottery() public {
        // Using block.prevrandao (formerly difficulty) - still predictable
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % 100;
        if (random < 50) {
            (bool success, ) = payable(msg.sender).call{value: 0.1 ether}("");
            require(success);
        }
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

