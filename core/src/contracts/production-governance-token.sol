// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title Production Governance Token
 * @notice ERC20 token with governance and vesting features
 * @dev Contains various subtle security issues
 */
contract ProductionGovernanceToken is ERC20, Ownable, Pausable {
    
    // ============ State Variables ============
    
    uint256 public constant MAX_SUPPLY = 100_000_000 * 1e18;
    uint256 public constant VESTING_DURATION = 365 days;
    
    struct VestingSchedule {
        uint256 totalAmount;
        uint256 released;
        uint256 startTime;
        uint256 duration;
        bool revoked;
    }
    
    mapping(address => VestingSchedule) public vestingSchedules;
    address[] public vestingBeneficiaries; // VULNERABLE: Unbounded array
    
    mapping(address => bool) public whitelist;
    address[] public whitelistedAddresses; // VULNERABLE: Unbounded array
    
    uint256 public transferFee; // Basis points (100 = 1%)
    address public feeRecipient;
    
    // ============ Events ============
    
    event VestingCreated(address indexed beneficiary, uint256 amount, uint256 duration);
    event VestingReleased(address indexed beneficiary, uint256 amount);
    event VestingRevoked(address indexed beneficiary);
    event WhitelistUpdated(address indexed account, bool status);
    event TransferFeeUpdated(uint256 newFee);
    
    // ============ Constructor ============
    
    constructor(
        string memory name,
        string memory symbol,
        address _owner
    ) ERC20(name, symbol) {
        require(_owner != address(0), "Invalid owner");
        _transferOwnership(_owner);
        feeRecipient = _owner;
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get releasable amount for a beneficiary
     * @dev VULNERABLE: Unbounded loop if many beneficiaries
     */
    function getReleasableAmount(address beneficiary) public view returns (uint256) {
        VestingSchedule memory schedule = vestingSchedules[beneficiary];
        if (schedule.revoked || schedule.totalAmount == 0) {
            return 0;
        }
        
        if (block.timestamp < schedule.startTime) {
            return 0;
        }
        
        uint256 elapsed = block.timestamp - schedule.startTime;
        if (elapsed >= schedule.duration) {
            return schedule.totalAmount - schedule.released;
        }
        
        uint256 vested = schedule.totalAmount * elapsed / schedule.duration;
        return vested - schedule.released;
    }
    
    /**
     * @notice Get total releasable amount for all beneficiaries
     * @dev VULNERABLE: Unbounded loop - DoS risk
     */
    function getTotalReleasableAmount() external view returns (uint256 total) {
        for (uint256 i = 0; i < vestingBeneficiaries.length; i++) {
            total += getReleasableAmount(vestingBeneficiaries[i]);
        }
    }
    
    /**
     * @notice Get all whitelisted addresses
     * @dev VULNERABLE: Unbounded array return
     */
    function getWhitelistedAddresses() external view returns (address[] memory) {
        return whitelistedAddresses;
    }
    
    // ============ Token Functions ============
    
    /**
     * @notice Override transfer to include fee
     * @dev VULNERABLE: No slippage protection on fee calculation
     */
    function transfer(address to, uint256 amount) public override whenNotPaused returns (bool) {
        uint256 fee = amount * transferFee / 10000;
        uint256 amountAfterFee = amount - fee;
        
        if (fee > 0) {
            super.transfer(feeRecipient, fee);
        }
        
        return super.transfer(to, amountAfterFee);
    }
    
    /**
     * @notice Override transferFrom to include fee
     */
    function transferFrom(address from, address to, uint256 amount) public override whenNotPaused returns (bool) {
        uint256 fee = amount * transferFee / 10000;
        uint256 amountAfterFee = amount - fee;
        
        if (fee > 0) {
            super.transferFrom(from, feeRecipient, fee);
        }
        
        return super.transferFrom(from, to, amountAfterFee);
    }
    
    /**
     * @notice Approve spender
     * @dev VULNERABLE: Standard ERC20 approve - front-running risk
     */
    function approve(address spender, uint256 amount) public override returns (bool) {
        // VULNERABLE: No check for current allowance
        // If user wants to change from 5 to 3, attacker can front-run with 5->5 transaction
        return super.approve(spender, amount);
    }
    
    // ============ Vesting Functions ============
    
    /**
     * @notice Create vesting schedule
     */
    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 duration
    ) external onlyOwner {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(amount > 0, "Amount must be greater than 0");
        require(duration > 0, "Duration must be greater than 0");
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        require(vestingSchedules[beneficiary].totalAmount == 0, "Vesting already exists");
        
        vestingSchedules[beneficiary] = VestingSchedule({
            totalAmount: amount,
            released: 0,
            startTime: block.timestamp,
            duration: duration,
            revoked: false
        });
        
        vestingBeneficiaries.push(beneficiary);
        
        _mint(address(this), amount);
        
        emit VestingCreated(beneficiary, amount, duration);
    }
    
    /**
     * @notice Release vested tokens
     */
    function releaseVesting(address beneficiary) external {
        require(vestingSchedules[beneficiary].totalAmount > 0, "No vesting schedule");
        
        uint256 releasable = getReleasableAmount(beneficiary);
        require(releasable > 0, "No tokens to release");
        
        vestingSchedules[beneficiary].released += releasable;
        
        _transfer(address(this), beneficiary, releasable);
        
        emit VestingReleased(beneficiary, releasable);
    }
    
    /**
     * @notice Release all vested tokens for all beneficiaries
     * @dev VULNERABLE: Unbounded loop with external calls
     */
    function releaseAllVestings() external onlyOwner {
        // VULNERABLE: Unbounded loop - can exceed gas limit
        for (uint256 i = 0; i < vestingBeneficiaries.length; i++) {
            address beneficiary = vestingBeneficiaries[i];
            uint256 releasable = getReleasableAmount(beneficiary);
            
            if (releasable > 0) {
                vestingSchedules[beneficiary].released += releasable;
                // VULNERABLE: External call in loop - one failure reverts all
                _transfer(address(this), beneficiary, releasable);
                emit VestingReleased(beneficiary, releasable);
            }
        }
    }
    
    /**
     * @notice Revoke vesting schedule
     */
    function revokeVesting(address beneficiary) external onlyOwner {
        require(vestingSchedules[beneficiary].totalAmount > 0, "No vesting schedule");
        require(!vestingSchedules[beneficiary].revoked, "Already revoked");
        
        vestingSchedules[beneficiary].revoked = true;
        
        uint256 unreleased = vestingSchedules[beneficiary].totalAmount - 
                            vestingSchedules[beneficiary].released;
        
        if (unreleased > 0) {
            _burn(address(this), unreleased);
        }
        
        emit VestingRevoked(beneficiary);
    }
    
    // ============ Whitelist Functions ============
    
    /**
     * @notice Add address to whitelist
     */
    function addToWhitelist(address account) external onlyOwner {
        require(account != address(0), "Invalid address");
        require(!whitelist[account], "Already whitelisted");
        
        whitelist[account] = true;
        whitelistedAddresses.push(account);
        
        emit WhitelistUpdated(account, true);
    }
    
    /**
     * @notice Remove address from whitelist
     * @dev VULNERABLE: Expensive delete operation
     */
    function removeFromWhitelist(address account) external onlyOwner {
        require(whitelist[account], "Not whitelisted");
        
        whitelist[account] = false;
        
        // VULNERABLE: Delete from array - expensive operation
        for (uint256 i = 0; i < whitelistedAddresses.length; i++) {
            if (whitelistedAddresses[i] == account) {
                delete whitelistedAddresses[i];
                break;
            }
        }
        
        emit WhitelistUpdated(account, false);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Mint new tokens
     */
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address");
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }
    
    /**
     * @notice Set transfer fee
     */
    function setTransferFee(uint256 _transferFee) external onlyOwner {
        require(_transferFee <= 1000, "Fee too high"); // Max 10%
        transferFee = _transferFee;
        emit TransferFeeUpdated(_transferFee);
    }
    
    /**
     * @notice Set fee recipient
     */
    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        require(_feeRecipient != address(0), "Invalid address");
        feeRecipient = _feeRecipient;
    }
    
    /**
     * @notice Pause contract
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @notice Unpause contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }
}




