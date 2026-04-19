// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Modern Staking Vault - Tests self-service pattern detection
/// Users should be able to stake/unstake/claim without triggering access control warnings
contract ModernStakingVault {
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public lastUpdateTime;
    
    uint256 public rewardRate = 100; // rewards per second
    uint256 public totalStaked;
    address public owner;
    bool public paused;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Self-service: User stakes their own tokens
    function stake() external payable {
        require(msg.value > 0, "Cannot stake 0");
        require(!paused, "Staking paused");
        
        _updateRewards(msg.sender);
        stakes[msg.sender] += msg.value;
        totalStaked += msg.value;
    }
    
    // Self-service: User unstakes their own tokens
    function unstake(uint256 amount) external {
        require(stakes[msg.sender] >= amount, "Insufficient stake");
        
        _updateRewards(msg.sender);
        stakes[msg.sender] -= amount;
        totalStaked -= amount;
        
        payable(msg.sender).transfer(amount);
    }
    
    // Self-service: User claims their own rewards
    function claimRewards() external {
        _updateRewards(msg.sender);
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");
        
        rewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }
    
    // Self-service: Combined unstake and claim
    function exit() external {
        uint256 stakedAmount = stakes[msg.sender];
        _updateRewards(msg.sender);
        
        uint256 reward = rewards[msg.sender];
        
        stakes[msg.sender] = 0;
        rewards[msg.sender] = 0;
        totalStaked -= stakedAmount;
        
        payable(msg.sender).transfer(stakedAmount + reward);
    }
    
    // Internal helper - lower reentrancy risk
    function _updateRewards(address user) internal {
        if (stakes[user] > 0) {
            uint256 timeElapsed = block.timestamp - lastUpdateTime[user];
            rewards[user] += (stakes[user] * rewardRate * timeElapsed) / 1e18;
        }
        lastUpdateTime[user] = block.timestamp;
    }
    
    // Private helper - minimal reentrancy risk
    function _calculateReward(address user) private view returns (uint256) {
        if (stakes[user] == 0) return 0;
        uint256 timeElapsed = block.timestamp - lastUpdateTime[user];
        return (stakes[user] * rewardRate * timeElapsed) / 1e18;
    }
    
    // Admin only: Should require access control
    function setRewardRate(uint256 newRate) external {
        require(msg.sender == owner, "Only owner");
        rewardRate = newRate;
    }
    
    // Admin only: Should require access control
    function pause() external {
        require(msg.sender == owner, "Only owner");
        paused = true;
    }
    
    // Admin only: Should require access control
    function unpause() external {
        require(msg.sender == owner, "Only owner");
        paused = false;
    }
    
    // View function: No reentrancy risk
    function pendingRewards(address user) external view returns (uint256) {
        return rewards[user] + _calculateReward(user);
    }
}








