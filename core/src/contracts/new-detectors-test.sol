// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0; // Pre-0.8 for integer overflow tests

// Test: Integer Overflow (pre-0.8 without SafeMath)
contract IntegerOverflowTest {
    uint256 public balance;
    
    // VULNERABLE: No SafeMath
    function add(uint256 amount) public {
        balance += amount; // Overflow possible
    }
    
    function sub(uint256 amount) public {
        balance -= amount; // Underflow possible
    }
    
    function mul(uint256 amount) public {
        balance = balance * amount; // Overflow possible
    }
}

// Test: Flash Loan Vulnerability
contract FlashLoanVulnerable {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: Uses spot price
    function getPrice(address pair) public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = IUniswapPair(pair).getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1); // Spot price!
    }
    
    // VULNERABLE: Unvalidated callback
    function uniswapV2Callback(uint amount0, uint amount1, bytes calldata data) external {
        // No msg.sender validation!
        balances[tx.origin] += amount0;
    }
    
    // VULNERABLE: Balance-based swap
    function swap(address token) public {
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "No balance");
        // ... swap logic based on manipulable balance
    }
}

// Base contract for proxy tests
abstract contract Upgradeable {}

// Test: Storage Collision (Proxy)
contract StorageCollisionTest is Upgradeable {
    uint256 public value;
    address public admin;
    mapping(address => uint256) public data;
    // MISSING: uint256[50] private __gap;
    
    // VULNERABLE: Constructor in upgradeable
    constructor(address _admin) {
        admin = _admin; // Won't run for proxy!
    }
    
    // VULNERABLE: Unprotected initializer
    function initialize(address _admin) public {
        // Missing initializer modifier!
        admin = _admin;
    }
}

// Test: Front-Running
contract FrontRunningTest {
    mapping(address => uint256) public allowances;
    
    // VULNERABLE: Race condition on approve
    function approve(address spender, uint256 amount) public {
        allowances[spender] = amount; // Can be front-run
    }
    
    // VULNERABLE: Swap without slippage
    function swap(address tokenIn, address tokenOut, uint256 amountIn) public {
        // No minAmountOut!
        // No deadline!
    }
    
    // VULNERABLE: Open bid auction
    function bid() public payable {
        require(msg.value > highestBid, "Too low");
        highestBid = msg.value; // Visible in mempool
    }
    
    uint256 public highestBid;
}

// Test: DoS via Unbounded Loops
contract DoSLoopTest {
    address[] public users;
    mapping(address => uint256) public balances;
    
    function addUser(address user) public {
        users.push(user); // Array grows forever
    }
    
    // VULNERABLE: Unbounded loop with external calls
    function distributeRewards() public {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether); // DoS if one fails
        }
    }
    
    // VULNERABLE: Unbounded loop with storage writes
    function resetAll() public {
        for (uint i = 0; i < users.length; i++) {
            balances[users[i]] = 0; // Gas limit
        }
    }
    
    // VULNERABLE: Delete in loop
    function clearUsers() public {
        for (uint i = 0; i < users.length; i++) {
            delete users[i]; // Expensive
        }
    }
}

// Test: Unchecked ERC20
contract UncheckedERC20Test {
    IERC20 public token;
    
    // VULNERABLE: Unchecked transfer
    function unsafeTransfer(address to, uint256 amount) public {
        token.transfer(to, amount); // Return not checked
    }
    
    // VULNERABLE: Unchecked transferFrom
    function unsafeTransferFrom(address from, uint256 amount) public {
        token.transferFrom(from, address(this), amount); // Return not checked
    }
    
    // VULNERABLE: Unchecked approve
    function unsafeApprove(address spender, uint256 amount) public {
        token.approve(spender, amount); // Return not checked
    }
}

// Interfaces
interface IUniswapPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}