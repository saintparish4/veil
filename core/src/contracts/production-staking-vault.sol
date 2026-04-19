// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title Production Staking Vault
 * @notice A production-grade staking contract with comprehensive security measures
 * @dev This contract demonstrates best practices for secure DeFi staking
 */
contract ProductionStakingVault is ReentrancyGuard, Ownable, Pausable {
    using SafeERC20 for IERC20;

    // ============ State Variables ============
    
    IERC20 public immutable stakingToken;
    IERC20 public immutable rewardToken;
    
    uint256 public totalStaked;
    uint256 public rewardRate; // tokens per second
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    
    uint256 public constant MIN_STAKE = 1e18;
    uint256 public constant MAX_STAKE = 1000000e18;
    uint256 public constant REWARD_DURATION = 30 days;
    
    struct StakerInfo {
        uint256 balance;
        uint256 rewardDebt;
        uint256 lastStakeTime;
    }
    
    mapping(address => StakerInfo) public stakers;
    
    // ============ Events ============
    
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event RewardRateUpdated(uint256 newRate);
    
    // ============ Constructor ============
    
    constructor(
        address _stakingToken,
        address _rewardToken,
        address _owner
    ) {
        require(_stakingToken != address(0), "Invalid staking token");
        require(_rewardToken != address(0), "Invalid reward token");
        require(_owner != address(0), "Invalid owner");
        
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        _transferOwnership(_owner);
    }
    
    // ============ Modifiers ============
    
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            stakers[account].rewardDebt = earned(account);
        }
        _;
    }
    
    // ============ View Functions ============
    
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored + 
               (block.timestamp - lastUpdateTime) * rewardRate * 1e18 / totalStaked;
    }
    
    function earned(address account) public view returns (uint256) {
        StakerInfo memory staker = stakers[account];
        return (staker.balance * (rewardPerToken() - staker.rewardDebt)) / 1e18;
    }
    
    function getStakerInfo(address account) external view returns (
        uint256 balance,
        uint256 pendingRewards,
        uint256 lastStakeTime
    ) {
        StakerInfo memory staker = stakers[account];
        return (
            staker.balance,
            earned(account),
            staker.lastStakeTime
        );
    }
    
    // ============ User Functions ============
    
    /**
     * @notice Stake tokens into the vault
     * @param amount Amount of tokens to stake
     */
    function stake(uint256 amount) external nonReentrant whenNotPaused updateReward(msg.sender) {
        require(amount >= MIN_STAKE, "Amount below minimum");
        require(amount <= MAX_STAKE, "Amount above maximum");
        
        StakerInfo storage staker = stakers[msg.sender];
        require(staker.balance + amount <= MAX_STAKE, "Total stake exceeds maximum");
        
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        
        staker.balance += amount;
        staker.lastStakeTime = block.timestamp;
        totalStaked += amount;
        
        emit Staked(msg.sender, amount);
    }
    
    /**
     * @notice Withdraw staked tokens
     * @param amount Amount of tokens to withdraw
     */
    function withdraw(uint256 amount) external nonReentrant updateReward(msg.sender) {
        StakerInfo storage staker = stakers[msg.sender];
        require(staker.balance >= amount, "Insufficient balance");
        require(block.timestamp >= staker.lastStakeTime + 7 days, "Cooldown period active");
        
        staker.balance -= amount;
        totalStaked -= amount;
        
        stakingToken.safeTransfer(msg.sender, amount);
        
        emit Withdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant updateReward(msg.sender) {
        uint256 reward = earned(msg.sender);
        require(reward > 0, "No rewards to claim");
        
        stakers[msg.sender].rewardDebt = rewardPerToken();
        
        rewardToken.safeTransfer(msg.sender, reward);
        
        emit RewardClaimed(msg.sender, reward);
    }
    
    /**
     * @notice Withdraw all staked tokens and claim rewards
     */
    function exit() external {
        withdraw(stakers[msg.sender].balance);
        claimRewards();
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Update the reward rate (only owner)
     * @param newRate New reward rate per second
     */
    function setRewardRate(uint256 newRate) external onlyOwner updateReward(address(0)) {
        require(newRate > 0, "Invalid rate");
        rewardRate = newRate;
        emit RewardRateUpdated(newRate);
    }
    
    /**
     * @notice Emergency pause function
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @notice Unpause function
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @notice Emergency withdraw function for owner (only in extreme cases)
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        require(token != address(stakingToken), "Cannot withdraw staking token");
        IERC20(token).safeTransfer(owner(), amount);
    }
}







