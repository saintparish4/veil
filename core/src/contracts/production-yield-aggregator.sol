// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title Production Yield Aggregator
 * @notice Aggregates yield from multiple DeFi protocols
 * @dev This contract looks secure but has critical vulnerabilities
 */
contract ProductionYieldAggregator is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    // ============ State Variables ============
    
    IERC20 public immutable token;
    address public strategy;
    
    uint256 public totalDeposits;
    uint256 public totalShares;
    
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public shares;
    
    // ============ Events ============
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event StrategyUpdated(address newStrategy);
    
    // ============ Constructor ============
    
    constructor(address _token, address _owner) {
        require(_token != address(0), "Invalid token");
        require(_owner != address(0), "Invalid owner");
        token = IERC20(_token);
        _transferOwnership(_owner);
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get current price per share
     * @dev VULNERABLE: Uses spot price from DEX - can be manipulated via flash loans
     */
    function getPricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        
        // Get reserves from Uniswap V2 pair
        address pair = getPairAddress();
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pair).getReserves();
        
        // Calculate price based on spot reserves
        uint256 price = uint256(reserve0) * 1e18 / uint256(reserve1);
        
        return price;
    }
    
    /**
     * @notice Calculate shares for deposit amount
     */
    function calculateShares(uint256 amount) public view returns (uint256) {
        if (totalShares == 0) {
            return amount;
        }
        uint256 price = getPricePerShare();
        return amount * 1e18 / price;
    }
    
    /**
     * @notice Get user's balance
     */
    function balanceOf(address user) external view returns (uint256) {
        return shares[user] * getPricePerShare() / 1e18;
    }
    
    // ============ User Functions ============
    
    /**
     * @notice Deposit tokens
     * @dev VULNERABLE: Price manipulation can affect share calculation
     */
    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        
        token.safeTransferFrom(msg.sender, address(this), amount);
        
        uint256 shareAmount = calculateShares(amount);
        
        deposits[msg.sender] += amount;
        shares[msg.sender] += shareAmount;
        totalDeposits += amount;
        totalShares += shareAmount;
        
        emit Deposited(msg.sender, amount);
    }
    
    /**
     * @notice Withdraw tokens
     * @param amount Amount of tokens to withdraw
     * @dev VULNERABLE: No slippage protection - can be front-run
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be greater than 0");
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        
        uint256 price = getPricePerShare();
        uint256 shareAmount = amount * 1e18 / price;
        
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        
        deposits[msg.sender] -= amount;
        shares[msg.sender] -= shareAmount;
        totalDeposits -= amount;
        totalShares -= shareAmount;
        
        // VULNERABLE: No minimum output check - vulnerable to sandwich attacks
        token.safeTransfer(msg.sender, amount);
        
        emit Withdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Swap tokens via DEX
     * @param tokenIn Input token
     * @param tokenOut Output token
     * @param amountIn Input amount
     * @dev VULNERABLE: Missing slippage protection
     */
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        require(tokenIn != address(0) && tokenOut != address(0), "Invalid tokens");
        
        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
        
        // Simulate swap - in real implementation would call DEX router
        // VULNERABLE: No minAmountOut parameter
        uint256 amountOut = calculateSwapOutput(tokenIn, tokenOut, amountIn);
        
        IERC20(tokenOut).safeTransfer(msg.sender, amountOut);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Update strategy address
     */
    function setStrategy(address _strategy) external onlyOwner {
        require(_strategy != address(0), "Invalid strategy");
        strategy = _strategy;
        emit StrategyUpdated(_strategy);
    }
    
    // ============ Internal Functions ============
    
    function getPairAddress() internal pure returns (address) {
        // Simplified - would get actual pair address in production
        return address(0x1234567890123456789012345678901234567890);
    }
    
    function calculateSwapOutput(address, address, uint256 amountIn) internal pure returns (uint256) {
        // Simplified calculation - would use actual DEX logic
        return amountIn * 95 / 100; // 5% fee
    }
}

// ============ Interfaces ============

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}







