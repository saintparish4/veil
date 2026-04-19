// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Cross-Chain Bridge - Tests visibility-aware reentrancy detection
/// Mix of public, external, internal, and private functions
contract CrossChainBridge {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processedTransfers;
    mapping(address => uint256) public nonces;
    
    address public owner;
    address public relayer;
    uint256 public bridgeFee = 0.001 ether;
    
    event Deposit(address indexed user, uint256 amount, bytes32 indexed transferId);
    event Withdraw(address indexed user, uint256 amount);
    event BridgeTransfer(address indexed from, address indexed to, uint256 amount);
    
    constructor(address _relayer) {
        owner = msg.sender;
        relayer = _relayer;
    }
    
    // External: User deposits to bridge (high reentrancy risk)
    function deposit() external payable {
        require(msg.value > bridgeFee, "Amount too low");
        
        uint256 amount = msg.value - bridgeFee;
        bytes32 transferId = keccak256(abi.encodePacked(msg.sender, amount, nonces[msg.sender]++));
        
        // VULNERABLE: External call before state change
        (bool success, ) = relayer.call{value: bridgeFee}("");
        require(success, "Fee transfer failed");
        
        balances[msg.sender] += amount; // State change after external call
        
        emit Deposit(msg.sender, amount, transferId);
    }
    
    // External: User withdraws from bridge (high reentrancy risk)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: External call before state change
        payable(msg.sender).transfer(amount);
        
        balances[msg.sender] -= amount; // State change after external call
        
        emit Withdraw(msg.sender, amount);
    }
    
    // Public: Process bridge transfer (high reentrancy risk)
    function processBridgeTransfer(
        address to,
        uint256 amount,
        bytes32 transferId
    ) public {
        require(msg.sender == relayer, "Only relayer");
        require(!processedTransfers[transferId], "Already processed");
        
        processedTransfers[transferId] = true;
        
        // External call before updating balance
        payable(to).transfer(amount);
        balances[to] += amount;
        
        emit BridgeTransfer(msg.sender, to, amount);
    }
    
    // Public: Batch process (safe - no external calls)
    function batchProcess(
        address[] calldata recipients,
        uint256[] calldata amounts
    ) public {
        require(msg.sender == relayer, "Only relayer");
        require(recipients.length == amounts.length, "Length mismatch");
        
        for (uint256 i = 0; i < recipients.length; i++) {
            _creditBalance(recipients[i], amounts[i]);
        }
    }
    
    // Internal: Credit balance (lower reentrancy risk)
    function _creditBalance(address user, uint256 amount) internal {
        balances[user] += amount;
        
        // Even though this makes an external call, it's internal so lower risk
        if (amount > 1 ether) {
            (bool success, ) = user.call{value: 0}(""); // Notify user
            require(success);
        }
    }
    
    // Internal: Debit balance (lower reentrancy risk)
    function _debitBalance(address user, uint256 amount) internal {
        require(balances[user] >= amount, "Insufficient balance");
        balances[user] -= amount;
    }
    
    // Private: Calculate fee (minimal risk)
    function _calculateFee(uint256 amount) private view returns (uint256) {
        return (amount * 10) / 10000; // 0.1%
    }
    
    // Private: Validate transfer (minimal risk)
    function _validateTransfer(bytes32 transferId) private view returns (bool) {
        return !processedTransfers[transferId];
    }
    
    // Self-service: User claims refund for failed transfer
    function claimRefund(bytes32 transferId) external {
        require(!processedTransfers[transferId], "Transfer processed");
        
        // In real implementation, would validate failure proof
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
    
    // Self-service: User increases their balance (deposit-like)
    function increaseBalance() external payable {
        require(msg.value > 0, "Must send value");
        balances[msg.sender] += msg.value;
    }
    
    // Owner: Set bridge fee
    function setBridgeFee(uint256 newFee) external {
        require(msg.sender == owner, "Only owner");
        bridgeFee = newFee;
    }
    
    // Owner: Set relayer
    function setRelayer(address newRelayer) external {
        require(msg.sender == owner, "Only owner");
        relayer = newRelayer;
    }
    
    // DANGEROUS: Missing access control
    function emergencyDrain(address to) external {
        // Should require owner check!
        payable(to).transfer(address(this).balance);
    }
    
    // View: Get balance
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
    
    // View: Check if transfer processed
    function isProcessed(bytes32 transferId) external view returns (bool) {
        return processedTransfers[transferId];
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}








