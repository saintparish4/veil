# Smart Contract Test Suite

This directory contains a comprehensive suite of test contracts for the scanner. The contracts are organized to efficiently test all vulnerability detection features while minimizing redundancy.

## Contract Organization (9 files, down from 23!)

### Core Test Contracts

#### 1. **test-patterns.sol** (280 lines)
Consolidated safe vs vulnerable patterns for all 7 vulnerability types side by side.

**Replaces 15 old files** with one comprehensive comparison:
- ✅ Reentrancy (safe vs vulnerable)
- ✅ Unchecked calls (safe vs vulnerable)
- ✅ tx.origin (safe vs vulnerable)
- ✅ Access control (safe vs vulnerable)
- ✅ Delegatecall (safe vs vulnerable)
- ✅ Timestamp dependence (safe vs vulnerable)
- ✅ Unsafe randomness (safe vs vulnerable)

**Why This Works Better:**
- Side-by-side comparison shows correct vs incorrect patterns
- Easy to see exactly what makes code safe or vulnerable
- Single file to scan instead of jumping between 16 files

---

#### 2. **comprehensive-vulnerabilities.sol** (66 lines)
All 7 vulnerabilities in one contract - perfect for batch testing.

Tests all detectors simultaneously:
- Reentrancy
- Unchecked calls
- tx.origin authentication
- Missing access control
- Dangerous delegatecall
- Timestamp dependence
- Unsafe randomness

**Use Case:** Quick smoke test to verify all detectors work

---

### Modern 2025 DeFi Contracts

These test the new heuristics (self-service + visibility-aware reentrancy):

#### 3. **modern-staking-vault.sol** (103 lines)
Modern staking vault with rewards.

**Tests:**
- ✅ Self-service: stake(), unstake(), claimRewards(), exit()
- ✅ Visibility: internal/private helpers (lower reentrancy risk)
- ✅ Admin functions with proper access control

---

#### 4. **defi-yield-aggregator.sol** (121 lines)
ERC-4626-style vault with share-based accounting.

**Tests:**
- ✅ Self-service: deposit(), withdraw(), withdrawAll(), redeem()
- ✅ Share-based vault pattern (2025 standard)
- ✅ Internal harvest function (lower risk)

---

#### 5. **nft-staking-rewards.sol** (168 lines)
NFT staking for ERC20 rewards.

**Tests:**
- ✅ Self-service: stake(), unstake(), claimRewards(), harvest(), compound()
- ✅ Reentrancy guards (nonReentrant)
- ✅ Internal/private helpers

---

#### 6. **modern-liquidity-pool.sol** (163 lines)
AMM-style liquidity pool.

**Tests:**
- ✅ Self-service: addLiquidity(), removeLiquidity()
- ✅ Public swap() function
- ✅ Internal/private calculation functions
- ⚠️ Intentional missing access control

---

#### 7. **governance-timelock.sol** (170 lines)
Modern governance with timelock.

**Tests:**
- ✅ Self-service: delegate(), undelegate()
- ⚠️ **Intentional vulnerabilities:** Missing access control on 4 sensitive functions
  - setDelay()
  - transferAdmin()
  - upgradeImplementation()
  - terminate()

---

#### 8. **rewards-distributor.sol** (186 lines)
Rewards distribution with operator pattern.

**Tests:**
- ✅ Self-service: claim(), claimAll(), compound()
- ✅ Proper modifiers: onlyOwner, onlyOperator
- ⚠️ **Intentional vulnerabilities:** 5 functions missing access control
  - transferOwnership()
  - setTreasury()
  - withdrawTo() (NOT self-service - has arbitrary 'to')
  - pause()/unpause()

---

#### 9. **cross-chain-bridge.sol** (153 lines)
Cross-chain bridge testing visibility-aware reentrancy.

**Tests:**
- ⚠️ **External** functions (high risk): deposit(), withdraw()
- ⚠️ **Public** functions (high risk): processBridgeTransfer()
- ✅ **Internal** functions (lower risk): _creditBalance(), _debitBalance()
- ✅ **Private** functions (minimal risk): _calculateFee(), _validateTransfer()
- ✅ Self-service: claimRefund(), increaseBalance()
- ⚠️ Missing access control: emergencyDrain()

**Expected Reentrancy Severity:**
- External/Public → **CRITICAL/HIGH**
- Internal → **MEDIUM** (visibility-aware)
- Private → **SKIP/LOW** (zero external risk)

---

## File Reduction Summary

### Before (23 files):
- token.sol
- comprehensive-vulnerabilities.sol
- multiple-vulnerabilities.sol
- reentrancy-vulnerable.sol + reentrancy-safe.sol
- unchecked-call-vulnerable.sol + unchecked-call-safe.sol
- tx-origin-vulnerable.sol + tx-origin-safe.sol
- access-control-safe.sol
- delegatecall-vulnerable.sol + delegatecall-safe.sol
- timestamp-vulnerable.sol + timestamp-safe.sol
- randomness-vulnerable.sol + randomness-safe.sol
- (Plus 7 new modern contracts)

### After (9 files):
- **test-patterns.sol** ← Replaces 15 files!
- comprehensive-vulnerabilities.sol
- modern-staking-vault.sol
- defi-yield-aggregator.sol
- nft-staking-rewards.sol
- modern-liquidity-pool.sol
- governance-timelock.sol
- rewards-distributor.sol
- cross-chain-bridge.sol

**Result: 61% fewer files, same coverage, better organization!**

---

## Running Scans

Scan all contracts:
```bash
cd core
cargo run -- scan contracts/ --recursive
```

Scan specific patterns:
```bash
# Test all vulnerability patterns
cargo run -- scan contracts/test-patterns.sol

# Test all vulnerabilities at once
cargo run -- scan contracts/comprehensive-vulnerabilities.sol

# Test self-service detection
cargo run -- scan contracts/modern-staking-vault.sol

# Test visibility-aware reentrancy
cargo run -- scan contracts/cross-chain-bridge.sol
```

JSON output:
```bash
cargo run -- scan contracts/ --recursive --format json > scan-results.json
```

---

## What Each File Tests

| File | Reentrancy | Access Control | Self-Service | Visibility | Other |
|------|-----------|----------------|--------------|-----------|-------|
| test-patterns.sol | ✅ | ✅ | ❌ | ❌ | All 7 types |
| comprehensive-vulnerabilities.sol | ✅ | ✅ | ❌ | ❌ | All 7 types |
| modern-staking-vault.sol | ✅ | ✅ | ✅ | ✅ | ERC-4626-like |
| defi-yield-aggregator.sol | ✅ | ✅ | ✅ | ✅ | Share-based |
| nft-staking-rewards.sol | ✅ | ✅ | ✅ | ✅ | NFT staking |
| modern-liquidity-pool.sol | ✅ | ✅ | ✅ | ✅ | AMM pattern |
| governance-timelock.sol | ❌ | ✅ | ✅ | ❌ | Timelock |
| rewards-distributor.sol | ✅ | ✅ | ✅ | ✅ | Operators |
| cross-chain-bridge.sol | ✅ | ✅ | ✅ | ✅ | Bridge |

---

## Expected Results

### test-patterns.sol
Should detect:
- 7 vulnerable contracts with various severity levels
- 7 safe contracts with no warnings

### comprehensive-vulnerabilities.sol
Should detect:
- 7 different vulnerabilities in one contract
- All severity levels represented

### Modern contracts
Should demonstrate:
- ✅ No false positives on self-service functions
- ✅ Visibility-aware severity adjustments
- ✅ Proper detection of intentional vulnerabilities
- ✅ Recognition of reentrancy guards

---

## Success Criteria

The scanner should:
1. **Detect all vulnerabilities** in test-patterns.sol and comprehensive-vulnerabilities.sol
2. **Zero false positives** on self-service functions (stake, withdraw, claim, etc.)
3. **Adjust severity** based on function visibility (external > public > internal > private)
4. **Recognize** reentrancy guards and skip protected functions
5. **Catch** intentionally vulnerable admin functions

This represents a complete, realistic test suite for 2025 smart contract security!
