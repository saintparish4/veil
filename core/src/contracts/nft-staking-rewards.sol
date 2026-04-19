// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// NFT Staking with ERC20 Rewards - Modern 2025 pattern
/// Tests self-service staking/unstaking with visibility variations
contract NFTStakingRewards {
    struct UserInfo {
        uint256[] stakedTokenIds;
        uint256 rewardDebt;
        uint256 pendingRewards;
        uint256 lastClaimTime;
    }
    
    mapping(address => UserInfo) public userInfo;
    mapping(uint256 => address) public tokenOwner;
    
    address public nftContract;
    address public rewardToken;
    address public owner;
    
    uint256 public rewardPerNFTPerDay = 10e18; // 10 tokens per NFT per day
    uint256 public totalStaked;
    
    bool private locked;
    
    modifier nonReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }
    
    constructor(address _nft, address _reward) {
        nftContract = _nft;
        rewardToken = _reward;
        owner = msg.sender;
    }
    
    // Self-service: User stakes their own NFT
    function stake(uint256 tokenId) external nonReentrant {
        _updateRewards(msg.sender);
        
        // Transfer NFT from user to this contract
        // (bool success, ) = nftContract.call(
        //     abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), tokenId)
        // );
        // require(success, "NFT transfer failed");
        
        userInfo[msg.sender].stakedTokenIds.push(tokenId);
        tokenOwner[tokenId] = msg.sender;
        totalStaked++;
    }
    
    // Self-service: User stakes multiple NFTs
    function stakeMultiple(uint256[] calldata tokenIds) external nonReentrant {
        _updateRewards(msg.sender);
        
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            userInfo[msg.sender].stakedTokenIds.push(tokenId);
            tokenOwner[tokenId] = msg.sender;
        }
        
        totalStaked += tokenIds.length;
    }
    
    // Self-service: User unstakes their own NFT
    function unstake(uint256 tokenId) external nonReentrant {
        require(tokenOwner[tokenId] == msg.sender, "Not owner");
        
        _updateRewards(msg.sender);
        _removeTokenId(msg.sender, tokenId);
        
        tokenOwner[tokenId] = address(0);
        totalStaked--;
        
        // Transfer NFT back to user
        // (bool success, ) = nftContract.call(
        //     abi.encodeWithSignature("transferFrom(address,address,uint256)", address(this), msg.sender, tokenId)
        // );
        // require(success, "NFT transfer failed");
    }
    
    // Self-service: User claims their rewards
    function claimRewards() external nonReentrant {
        _updateRewards(msg.sender);
        
        uint256 pending = userInfo[msg.sender].pendingRewards;
        require(pending > 0, "No rewards");
        
        userInfo[msg.sender].pendingRewards = 0;
        userInfo[msg.sender].lastClaimTime = block.timestamp;
        
        // Transfer reward tokens
        payable(msg.sender).transfer(pending);
    }
    
    // Self-service: Harvest (alias for claim)
    function harvest() external {
        _updateRewards(msg.sender);
        
        uint256 pending = userInfo[msg.sender].pendingRewards;
        if (pending > 0) {
            userInfo[msg.sender].pendingRewards = 0;
            userInfo[msg.sender].lastClaimTime = block.timestamp;
            payable(msg.sender).transfer(pending);
        }
    }
    
    // Self-service: Compound rewards (reinvest)
    function compound() external nonReentrant {
        _updateRewards(msg.sender);
        // In real implementation, would reinvest rewards
    }
    
    // Internal: Update user rewards
    function _updateRewards(address user) internal {
        UserInfo storage info = userInfo[user];
        
        if (info.stakedTokenIds.length > 0) {
            uint256 timeElapsed = block.timestamp - info.lastClaimTime;
            uint256 reward = (info.stakedTokenIds.length * rewardPerNFTPerDay * timeElapsed) / 1 days;
            info.pendingRewards += reward;
        }
    }
    
    // Private: Remove token from user's staked list
    function _removeTokenId(address user, uint256 tokenId) private {
        uint256[] storage tokens = userInfo[user].stakedTokenIds;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == tokenId) {
                tokens[i] = tokens[tokens.length - 1];
                tokens.pop();
                break;
            }
        }
    }
    
    // Admin: Set reward rate
    function setRewardRate(uint256 newRate) external {
        require(msg.sender == owner, "Only owner");
        rewardPerNFTPerDay = newRate;
    }
    
    // Admin: Emergency withdraw (should be restricted)
    function emergencyWithdraw(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        payable(to).transfer(amount);
    }
    
    // View: Check pending rewards
    function pendingReward(address user) external view returns (uint256) {
        UserInfo storage info = userInfo[user];
        if (info.stakedTokenIds.length == 0) return info.pendingRewards;
        
        uint256 timeElapsed = block.timestamp - info.lastClaimTime;
        uint256 newReward = (info.stakedTokenIds.length * rewardPerNFTPerDay * timeElapsed) / 1 days;
        return info.pendingRewards + newReward;
    }
    
    // View: Get user's staked NFTs
    function getStakedNFTs(address user) external view returns (uint256[] memory) {
        return userInfo[user].stakedTokenIds;
    }
}








