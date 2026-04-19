// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Modern Governance with Timelock - Tests access control patterns
/// Should properly detect missing access control on sensitive operations
contract GovernanceTimelock {
    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        bool executed;
        bool canceled;
    }
    
    mapping(bytes32 => Proposal) public proposals;
    mapping(address => bool) public guardians;
    mapping(address => uint256) public votingPower;
    
    address public admin;
    address public pendingAdmin;
    uint256 public delay = 2 days;
    uint256 public constant MINIMUM_DELAY = 1 days;
    uint256 public constant MAXIMUM_DELAY = 30 days;
    
    event ProposalQueued(bytes32 indexed proposalId, address target, uint256 eta);
    event ProposalExecuted(bytes32 indexed proposalId);
    event ProposalCanceled(bytes32 indexed proposalId);
    
    constructor() {
        admin = msg.sender;
        guardians[msg.sender] = true;
    }
    
    // Self-service: User delegates their voting power
    function delegate(address delegatee, uint256 amount) external {
        require(votingPower[msg.sender] >= amount, "Insufficient power");
        votingPower[msg.sender] -= amount;
        votingPower[delegatee] += amount;
    }
    
    // Self-service: User reclaims their delegated power
    function undelegate(uint256 amount) external {
        require(votingPower[msg.sender] >= amount, "Nothing to undelegate");
        // Simplified: In real system would track delegations
        votingPower[msg.sender] += amount;
    }
    
    // Public: Anyone can queue proposal (should this be restricted?)
    function queueProposal(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes32) {
        require(votingPower[msg.sender] > 0, "No voting power");
        
        bytes32 proposalId = keccak256(abi.encode(target, value, data, block.timestamp));
        uint256 eta = block.timestamp + delay;
        
        proposals[proposalId] = Proposal({
            target: target,
            value: value,
            data: data,
            eta: eta,
            executed: false,
            canceled: false
        });
        
        emit ProposalQueued(proposalId, target, eta);
        return proposalId;
    }
    
    // Public: Execute proposal after timelock
    function executeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Canceled");
        require(block.timestamp >= proposal.eta, "Timelock not expired");
        
        proposal.executed = true;
        
        (bool success, ) = proposal.target.call{value: proposal.value}(proposal.data);
        require(success, "Execution failed");
        
        emit ProposalExecuted(proposalId);
    }
    
    // Guardian only: Cancel proposal
    function cancelProposal(bytes32 proposalId) external {
        require(guardians[msg.sender], "Not guardian");
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.executed, "Already executed");
        
        proposal.canceled = true;
        emit ProposalCanceled(proposalId);
    }
    
    // Admin only: Set delay (MISSING ACCESS CONTROL - should be caught)
    function setDelay(uint256 newDelay) external {
        require(newDelay >= MINIMUM_DELAY, "Delay too short");
        require(newDelay <= MAXIMUM_DELAY, "Delay too long");
        delay = newDelay;
    }
    
    // Admin only: Add guardian (HAS ACCESS CONTROL)
    function addGuardian(address guardian) external {
        require(msg.sender == admin, "Only admin");
        guardians[guardian] = true;
    }
    
    // Admin only: Remove guardian (HAS ACCESS CONTROL)
    function removeGuardian(address guardian) external {
        require(msg.sender == admin, "Only admin");
        guardians[guardian] = false;
    }
    
    // Admin only: Transfer admin (MISSING ACCESS CONTROL - should be caught)
    function transferAdmin(address newAdmin) external {
        pendingAdmin = newAdmin;
    }
    
    // Pending admin: Accept admin role
    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }
    
    // DANGEROUS: Missing access control on upgrade (should be caught)
    function upgradeImplementation(address newImpl) external {
        // This should trigger missing access control warning
        (bool success, ) = newImpl.delegatecall(abi.encodeWithSignature("initialize()"));
        require(success, "Upgrade failed");
    }
    
    // DANGEROUS: Missing access control on selfdestruct (should be caught)
    function terminate() external {
        selfdestruct(payable(msg.sender));
    }
    
    // Internal: Validate proposal
    function _validateProposal(bytes32 proposalId) internal view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return !proposal.executed && !proposal.canceled;
    }
    
    // View: Check if address is guardian
    function isGuardian(address account) external view returns (bool) {
        return guardians[account];
    }
    
    // View: Get proposal details
    function getProposal(bytes32 proposalId) external view returns (
        address target,
        uint256 value,
        uint256 eta,
        bool executed,
        bool canceled
    ) {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.target,
            proposal.value,
            proposal.eta,
            proposal.executed,
            proposal.canceled
        );
    }
    
    receive() external payable {}
}








