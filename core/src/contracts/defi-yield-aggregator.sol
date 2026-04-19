// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// DeFi Yield Aggregator - Tests self-service deposits/withdrawals
/// Modern vault pattern with share-based accounting
contract YieldAggregator {
    mapping(address => uint256) private _balances;
    mapping(address => uint256) public shares;
    
    uint256 public totalShares;
    uint256 public totalAssets;
    address public strategy;
    address public governance;
    
    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdraw(address indexed user, uint256 amount, uint256 shares);
    
    constructor(address _strategy) {
        strategy = _strategy;
        governance = msg.sender;
    }
    
    // Self-service: User deposits their own funds
    function deposit(uint256 amount) external returns (uint256 sharesMinted) {
        require(amount > 0, "Cannot deposit 0");
        
        // Calculate shares (price per share increases with yield)
        sharesMinted = totalShares == 0 
            ? amount 
            : (amount * totalShares) / totalAssets;
        
        _balances[msg.sender] += amount;
        shares[msg.sender] += sharesMinted;
        totalShares += sharesMinted;
        totalAssets += amount;
        
        emit Deposit(msg.sender, amount, sharesMinted);
    }
    
    // Self-service: User withdraws their own funds
    function withdraw(uint256 shareAmount) external returns (uint256 amount) {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        
        // Calculate withdrawal amount based on current price per share
        amount = (shareAmount * totalAssets) / totalShares;
        
        shares[msg.sender] -= shareAmount;
        _balances[msg.sender] -= amount;
        totalShares -= shareAmount;
        totalAssets -= amount;
        
        payable(msg.sender).transfer(amount);
        emit Withdraw(msg.sender, amount, shareAmount);
    }
    
    // Self-service: Withdraw all user's shares
    function withdrawAll() external returns (uint256 amount) {
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "No shares");
        
        amount = (userShares * totalAssets) / totalShares;
        
        shares[msg.sender] = 0;
        _balances[msg.sender] -= amount;
        totalShares -= userShares;
        totalAssets -= amount;
        
        payable(msg.sender).transfer(amount);
        emit Withdraw(msg.sender, amount, userShares);
    }
    
    // Self-service: Redeem exact amount of assets
    function redeem(uint256 assets) external returns (uint256 sharesBurned) {
        sharesBurned = (assets * totalShares) / totalAssets;
        require(shares[msg.sender] >= sharesBurned, "Insufficient shares");
        
        shares[msg.sender] -= sharesBurned;
        _balances[msg.sender] -= assets;
        totalShares -= sharesBurned;
        totalAssets -= assets;
        
        payable(msg.sender).transfer(assets);
    }
    
    // Internal: Harvest yield from strategy
    function _harvest() internal returns (uint256 yield) {
        // Simulate yield harvest
        yield = address(this).balance - totalAssets;
        if (yield > 0) {
            totalAssets += yield;
        }
    }
    
    // Public: Anyone can trigger harvest (common pattern)
    function harvest() public returns (uint256) {
        return _harvest();
    }
    
    // Governance only: Update strategy
    function setStrategy(address newStrategy) external {
        require(msg.sender == governance, "Only governance");
        strategy = newStrategy;
    }
    
    // Governance only: Emergency withdraw to strategy
    function emergencyWithdrawToStrategy() external {
        require(msg.sender == governance, "Only governance");
        payable(strategy).transfer(address(this).balance);
    }
    
    // View functions
    function balanceOf(address user) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return (shares[user] * totalAssets) / totalShares;
    }
    
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return totalShares == 0 ? assets : (assets * totalShares) / totalAssets;
    }
    
    function previewWithdraw(uint256 shareAmount) external view returns (uint256) {
        return totalShares == 0 ? 0 : (shareAmount * totalAssets) / totalShares;
    }
}








