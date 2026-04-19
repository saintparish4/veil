// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Test Patterns - Safe vs Vulnerable implementations side by side
/// This replaces 16 separate files with one consolidated test suite

// ============================================================================
// REENTRANCY PATTERNS
// ============================================================================

/// VULNERABLE: State change after external call
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call before state change
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // Too late!
    }
}

/// SAFE: State change before external call (Checks-Effects-Interactions)
contract ReentrancySafe {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: State change before external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount; // State change first
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// ============================================================================
// UNCHECKED CALL PATTERNS
// ============================================================================

/// VULNERABLE: Unchecked external call return value
contract UncheckedCallVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Not checking return value
    function forwardFunds(address payable recipient) public {
        require(msg.sender == owner);
        recipient.call{value: address(this).balance}(""); // Ignoring return value
    }

    receive() external payable {}
}

/// SAFE: Checked external call return value
contract UncheckedCallSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: Checking return value
    function forwardFunds(address payable recipient) public {
        require(msg.sender == owner);
        
        (bool success, ) = recipient.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

// ============================================================================
// TX.ORIGIN PATTERNS
// ============================================================================

/// VULNERABLE: Using tx.origin for authentication
contract TxOriginVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin can be exploited via phishing
    function emergencyWithdraw() public {
        require(tx.origin == owner, "Not owner"); // Wrong!
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

/// SAFE: Using msg.sender for authentication
contract TxOriginSafe {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: msg.sender is the direct caller
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Not owner"); // Correct!
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}

// ============================================================================
// ACCESS CONTROL PATTERNS
// ============================================================================

/// VULNERABLE: Missing access control on sensitive functions
contract AccessControlVulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: Anyone can mint tokens
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    // VULNERABLE: Anyone can change owner
    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }

    // VULNERABLE: Anyone can destroy contract
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}

/// SAFE: Proper access control on sensitive functions
contract AccessControlSafe {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: Only owner can mint
    function mint(address to, uint256 amount) public {
        require(msg.sender == owner, "Only owner");
        balances[to] += amount;
    }

    // SAFE: Only owner can transfer ownership
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }

    // SAFE: Only owner can destroy
    function destroy() public {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(owner));
    }
}

// ============================================================================
// DELEGATECALL PATTERNS
// ============================================================================

/// VULNERABLE: Delegatecall to user-controlled address
contract DelegatecallVulnerable {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: User can provide malicious contract address
    function executeCode(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    receive() external payable {}
}

/// SAFE: Delegatecall only to trusted addresses
contract DelegatecallSafe {
    address public owner;
    address public immutable trustedLibrary;
    uint256 public value;

    constructor(address _trustedLibrary) {
        owner = msg.sender;
        trustedLibrary = _trustedLibrary;
    }

    // SAFE: Only calls trusted, immutable library
    function executeCode(bytes memory data) public {
        require(msg.sender == owner, "Only owner");
        (bool success, ) = trustedLibrary.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    receive() external payable {}
}

// ============================================================================
// TIMESTAMP DEPENDENCE PATTERNS
// ============================================================================

/// VULNERABLE: Exact timestamp checks and modulo operations
contract TimestampVulnerable {
    uint256 public prize = 1 ether;

    // VULNERABLE: Exact timestamp comparison
    function claimExactTime() public {
        require(block.timestamp == 1234567890, "Wrong time");
        payable(msg.sender).transfer(prize);
    }

    // VULNERABLE: Modulo with timestamp
    function claimModulo() public {
        require(block.timestamp % 15 == 0, "Not right time");
        payable(msg.sender).transfer(prize);
    }

    receive() external payable {}
}

/// SAFE: Reasonable timestamp ranges
contract TimestampSafe {
    uint256 public saleStart = block.timestamp;
    uint256 public saleEnd = block.timestamp + 30 days;

    // SAFE: Using timestamp for reasonable time ranges (>15 minutes)
    function buyTokens() public payable {
        require(block.timestamp >= saleStart, "Sale not started");
        require(block.timestamp <= saleEnd, "Sale ended");
        // Process purchase
    }

    // SAFE: Comparing ranges, not exact values
    function isActive() public view returns (bool) {
        return block.timestamp >= saleStart && block.timestamp <= saleEnd;
    }
}

// ============================================================================
// RANDOMNESS PATTERNS
// ============================================================================

/// VULNERABLE: Predictable randomness using block variables
contract RandomnessVulnerable {
    // VULNERABLE: Block variables are predictable
    function lottery1() public {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    // VULNERABLE: Block difficulty is predictable
    function lottery2() public {
        uint256 random = uint256(keccak256(abi.encodePacked(block.difficulty, msg.sender))) % 100;
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    // VULNERABLE: Block number is predictable
    function lottery3() public {
        uint256 random = uint256(keccak256(abi.encodePacked(block.number))) % 100;
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    // VULNERABLE: Blockhash is manipulable
    function lottery4() public {
        uint256 random = uint256(blockhash(block.number - 1)) % 100;
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    receive() external payable {}
}

/// SAFE: Using Chainlink VRF or commit-reveal
contract RandomnessSafe {
    mapping(bytes32 => uint256) public commitments;
    mapping(bytes32 => bool) public revealed;

    // SAFE: Commit-reveal pattern
    function commit(bytes32 commitment) public {
        commitments[commitment] = block.number;
    }

    function reveal(uint256 secret, uint256 choice) public {
        bytes32 commitment = keccak256(abi.encodePacked(secret, choice));
        require(commitments[commitment] > 0, "No commitment");
        require(!revealed[commitment], "Already revealed");
        require(block.number > commitments[commitment] + 1, "Too early");
        
        revealed[commitment] = true;
        
        // Use the revealed secret for randomness
        uint256 random = uint256(keccak256(abi.encodePacked(secret, blockhash(commitments[commitment])))) % 100;
        
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    // Note: In production, use Chainlink VRF for truly secure randomness
    
    receive() external payable {}
}








