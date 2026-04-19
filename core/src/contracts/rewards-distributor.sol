// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Rewards Distributor - Tests multiple patterns
/// Mix of safe self-service and potentially vulnerable admin functions
contract RewardsDistributor {
    struct UserRewards {
        uint256 claimed;
        uint256 pending;
        uint256 lastUpdate;
        uint256 multiplier; // 1e18 = 1x
    }
    
    mapping(address => UserRewards) public userRewards;
    mapping(address => bool) public operators;
    
    address public owner;
    address public treasury;
    uint256 public rewardRate = 1e18; // 1 token per second
    uint256 public totalDistributed;
    
    bool private _locked;
    
    event RewardsClaimed(address indexed user, uint256 amount);
    event RewardsUpdated(address indexed user, uint256 amount);
    event OperatorAdded(address indexed operator);
    
    modifier nonReentrant() {
        require(!_locked, "Locked");
        _locked = true;
        _;
        _locked = false;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyOperator() {
        require(operators[msg.sender], "Only operator");
        _;
    }
    
    constructor(address _treasury) {
        owner = msg.sender;
        treasury = _treasury;
        operators[msg.sender] = true;
    }
    
    // Self-service: User claims their own rewards (SAFE)
    function claim() external nonReentrant {
        _updateRewards(msg.sender);
        
        uint256 amount = userRewards[msg.sender].pending;
        require(amount > 0, "No rewards");
        
        userRewards[msg.sender].pending = 0;
        userRewards[msg.sender].claimed += amount;
        totalDistributed += amount;
        
        payable(msg.sender).transfer(amount);
        emit RewardsClaimed(msg.sender, amount);
    }
    
    // Self-service: User claims all rewards (SAFE)
    function claimAll() external nonReentrant {
        _updateRewards(msg.sender);
        
        uint256 pending = userRewards[msg.sender].pending;
        require(pending > 0, "No rewards");
        
        userRewards[msg.sender].pending = 0;
        userRewards[msg.sender].claimed += pending;
        totalDistributed += pending;
        
        payable(msg.sender).transfer(pending);
        emit RewardsClaimed(msg.sender, pending);
    }
    
    // Self-service: Compound rewards (SAFE)
    function compound() external nonReentrant {
        _updateRewards(msg.sender);
        
        uint256 amount = userRewards[msg.sender].pending;
        if (amount > 0) {
            userRewards[msg.sender].pending = 0;
            userRewards[msg.sender].multiplier += (amount * 1e18) / 1e20; // Increase multiplier
        }
    }
    
    // Public: Anyone can trigger update (is this safe?)
    function updateRewards(address user) public {
        _updateRewards(user);
    }
    
    // Operator only: Batch update (SAFE - has access control)
    function batchUpdateRewards(address[] calldata users) external onlyOperator {
        for (uint256 i = 0; i < users.length; i++) {
            _updateRewards(users[i]);
        }
    }
    
    // Internal: Calculate and update rewards
    function _updateRewards(address user) internal {
        UserRewards storage rewards = userRewards[user];
        
        if (rewards.lastUpdate == 0) {
            rewards.lastUpdate = block.timestamp;
            rewards.multiplier = 1e18;
            return;
        }
        
        uint256 timeElapsed = block.timestamp - rewards.lastUpdate;
        uint256 baseReward = (rewardRate * timeElapsed) / 1e18;
        uint256 boostedReward = (baseReward * rewards.multiplier) / 1e18;
        
        rewards.pending += boostedReward;
        rewards.lastUpdate = block.timestamp;
        
        emit RewardsUpdated(user, boostedReward);
    }
    
    // Private: Calculate base reward
    function _calculateBaseReward(address user) private view returns (uint256) {
        UserRewards storage rewards = userRewards[user];
        if (rewards.lastUpdate == 0) return 0;
        
        uint256 timeElapsed = block.timestamp - rewards.lastUpdate;
        return (rewardRate * timeElapsed) / 1e18;
    }
    
    // Owner: Set reward rate (SAFE - has access control)
    function setRewardRate(uint256 newRate) external onlyOwner {
        rewardRate = newRate;
    }
    
    // Owner: Add operator (SAFE - has access control)
    function addOperator(address operator) external onlyOwner {
        operators[operator] = true;
        emit OperatorAdded(operator);
    }
    
    // Owner: Remove operator (SAFE - has access control)
    function removeOperator(address operator) external onlyOwner {
        operators[operator] = false;
    }
    
    // DANGEROUS: Missing access control on ownership transfer
    function transferOwnership(address newOwner) external {
        // Should require msg.sender == owner but doesn't!
        owner = newOwner;
    }
    
    // DANGEROUS: Missing access control on treasury change
    function setTreasury(address newTreasury) external {
        // Should require msg.sender == owner but doesn't!
        treasury = newTreasury;
    }
    
    // DANGEROUS: Arbitrary withdrawal without access control
    function withdrawTo(address to, uint256 amount) external {
        // Should require msg.sender == owner but doesn't!
        // This is NOT self-service since it has arbitrary 'to' parameter
        payable(to).transfer(amount);
    }
    
    // Owner: Emergency withdraw (SAFE - has access control)
    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
    
    // DANGEROUS: Pause without access control
    function pause() external {
        // Should require access control
        _locked = true;
    }
    
    // DANGEROUS: Unpause without access control
    function unpause() external {
        // Should require access control
        _locked = false;
    }
    
    // View: Get pending rewards
    function pendingRewards(address user) external view returns (uint256) {
        UserRewards storage rewards = userRewards[user];
        uint256 baseReward = _calculateBaseReward(user);
        uint256 boostedReward = (baseReward * rewards.multiplier) / 1e18;
        return rewards.pending + boostedReward;
    }
    
    // View: Get user info
    function getUserInfo(address user) external view returns (
        uint256 claimed,
        uint256 pending,
        uint256 multiplier
    ) {
        UserRewards storage rewards = userRewards[user];
        return (
            rewards.claimed,
            rewards.pending,
            rewards.multiplier
        );
    }
    
    receive() external payable {}
}








