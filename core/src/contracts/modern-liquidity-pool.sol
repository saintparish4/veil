// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Modern AMM Liquidity Pool - Tests various patterns
/// Includes self-service LP operations and visibility variations
contract ModernLiquidityPool {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lpTokens;
    mapping(address => uint256) public rewards;
    
    uint256 public totalLiquidity;
    uint256 public totalLPTokens;
    uint256 public feeRate = 30; // 0.3%
    uint256 public protocolFee = 0;
    
    address public factory;
    address public governance;
    
    bool private locked;
    
    event LiquidityAdded(address indexed provider, uint256 amount, uint256 lpTokens);
    event LiquidityRemoved(address indexed provider, uint256 amount, uint256 lpTokens);
    event Swap(address indexed user, uint256 amountIn, uint256 amountOut);
    
    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        factory = msg.sender;
        governance = msg.sender;
    }
    
    // Self-service: User adds liquidity
    function addLiquidity() external payable nonReentrant returns (uint256 lpMinted) {
        require(msg.value > 0, "Must add liquidity");
        
        // Calculate LP tokens to mint
        lpMinted = totalLPTokens == 0 
            ? msg.value 
            : (msg.value * totalLPTokens) / totalLiquidity;
        
        deposits[msg.sender] += msg.value;
        lpTokens[msg.sender] += lpMinted;
        totalLiquidity += msg.value;
        totalLPTokens += lpMinted;
        
        emit LiquidityAdded(msg.sender, msg.value, lpMinted);
    }
    
    // Self-service: User removes liquidity
    function removeLiquidity(uint256 lpAmount) external nonReentrant returns (uint256 amount) {
        require(lpTokens[msg.sender] >= lpAmount, "Insufficient LP tokens");
        
        // Calculate amount to return
        amount = (lpAmount * totalLiquidity) / totalLPTokens;
        
        lpTokens[msg.sender] -= lpAmount;
        deposits[msg.sender] -= amount;
        totalLPTokens -= lpAmount;
        totalLiquidity -= amount;
        
        payable(msg.sender).transfer(amount);
        emit LiquidityRemoved(msg.sender, amount, lpAmount);
    }
    
    // Self-service: User removes all liquidity
    function removeLiquidityAll() external nonReentrant returns (uint256 amount) {
        uint256 userLP = lpTokens[msg.sender];
        require(userLP > 0, "No liquidity");
        
        amount = (userLP * totalLiquidity) / totalLPTokens;
        
        lpTokens[msg.sender] = 0;
        deposits[msg.sender] -= amount;
        totalLPTokens -= userLP;
        totalLiquidity -= amount;
        
        payable(msg.sender).transfer(amount);
        emit LiquidityRemoved(msg.sender, amount, userLP);
    }
    
    // Public: Anyone can swap (external call pattern)
    function swap(uint256 amountIn) external payable nonReentrant returns (uint256 amountOut) {
        require(msg.value == amountIn, "Amount mismatch");
        require(amountIn > 0, "Cannot swap 0");
        
        // Simple constant product formula
        uint256 fee = (amountIn * feeRate) / 10000;
        uint256 amountInWithFee = amountIn - fee;
        
        amountOut = _calculateSwapOutput(amountInWithFee);
        
        protocolFee += fee / 2; // 50% of fees to protocol
        totalLiquidity += fee / 2; // 50% to LPs
        
        payable(msg.sender).transfer(amountOut);
        emit Swap(msg.sender, amountIn, amountOut);
    }
    
    // Self-service: Claim LP rewards
    function claimRewards() external nonReentrant {
        _updateRewards(msg.sender);
        
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");
        
        rewards[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }
    
    // Internal: Calculate swap output
    function _calculateSwapOutput(uint256 amountIn) internal view returns (uint256) {
        // Simplified calculation
        return (amountIn * 99) / 100;
    }
    
    // Internal: Update rewards for LP
    function _updateRewards(address user) internal {
        if (lpTokens[user] > 0 && totalLPTokens > 0) {
            // Distribute accumulated fees proportionally
            uint256 userShare = (lpTokens[user] * 1e18) / totalLPTokens;
            uint256 userReward = (protocolFee * userShare) / 1e18;
            rewards[user] += userReward;
        }
    }
    
    // Private: Internal accounting helper
    function _adjustBalances(address user, uint256 amount) private {
        deposits[user] += amount;
    }
    
    // Governance: Set fee rate
    function setFeeRate(uint256 newFee) external {
        require(msg.sender == governance, "Only governance");
        require(newFee <= 1000, "Fee too high"); // Max 10%
        feeRate = newFee;
    }
    
    // Governance: Collect protocol fees
    function collectProtocolFees(address to) external {
        require(msg.sender == governance, "Only governance");
        uint256 fees = protocolFee;
        protocolFee = 0;
        payable(to).transfer(fees);
    }
    
    // Governance: Emergency pause (dangerous if no checks)
    function emergencyDrain(address to) external {
        require(msg.sender == governance, "Only governance");
        payable(to).transfer(address(this).balance);
    }
    
    // View functions
    function getUserLiquidity(address user) external view returns (uint256) {
        if (totalLPTokens == 0) return 0;
        return (lpTokens[user] * totalLiquidity) / totalLPTokens;
    }
    
    function previewAddLiquidity(uint256 amount) external view returns (uint256) {
        if (totalLPTokens == 0) return amount;
        return (amount * totalLPTokens) / totalLiquidity;
    }
    
    function previewRemoveLiquidity(uint256 lpAmount) external view returns (uint256) {
        if (totalLPTokens == 0) return 0;
        return (lpAmount * totalLiquidity) / totalLPTokens;
    }
}








