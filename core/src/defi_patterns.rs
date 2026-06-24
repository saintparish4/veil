//! DeFi protocol semantic classifiers.
//!
//! Pure functions — no Finding emission, no mutable state. Used by detectors to
//! identify protocol roles and suppress false positives on well-known DeFi patterns.

use crate::ast_utils::{find_nodes_of_kind, function_name, is_proxy_contract, node_text};
use crate::cfg::ControlFlowGraph;
use crate::taint::{find_taint_violations, CfgStatementKind, TaintQuery};
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Contract role
// ---------------------------------------------------------------------------

/// Coarse contract-level role classification used to adjust detector sensitivity.
///
/// Detectors should reduce false-positive severity for roles that legitimately
/// exhibit patterns that look dangerous out of context (e.g. flash loan receivers
/// that call out then write state as part of the lending protocol's required flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractRole {
    /// Contract whose primary purpose is executing flash loan callbacks.
    FlashLoanReceiver,
    /// Contract whose primary purpose is a Uniswap/fork AMM pool.
    UniswapPool,
    /// Contract implementing ERC-4626 tokenized vault interface.
    ERC4626Vault,
    /// Contract using a delegatecall proxy upgrade pattern.
    UpgradeableProxy,
    /// Governance timelock or multisig executor.
    GovernanceTimelock,
    /// Role could not be determined from static analysis.
    Unknown,
}

/// Classify the dominant protocol role of the contract(s) in `root`.
///
/// Checks are ordered from most specific to least specific. A file with both
/// an ERC-4626 vault and a flash loan receiver is classified as `FlashLoanReceiver`
/// because that role requires the most conservative false-positive handling.
pub fn classify_contract_role(root: &Node, source: &str) -> ContractRole {
    let funcs = find_nodes_of_kind(root, "function_definition");

    if funcs.iter().any(|f| is_flash_loan_receiver(f, source)) {
        return ContractRole::FlashLoanReceiver;
    }

    if funcs.iter().any(|f| is_uniswap_callback(f, source)) {
        return ContractRole::UniswapPool;
    }

    if is_erc4626_vault(root, source) {
        return ContractRole::ERC4626Vault;
    }

    if is_proxy_contract(root, source) || funcs.iter().any(|f| is_proxy_upgrade_function(f, source))
    {
        return ContractRole::UpgradeableProxy;
    }

    // Timelock: contract name contains "Timelock" or both schedule+execute functions exist
    let contracts = find_nodes_of_kind(root, "contract_declaration");
    for c in &contracts {
        let text = node_text(c, source);
        if text.contains("Timelock") || text.contains("TimeLock") {
            return ContractRole::GovernanceTimelock;
        }
    }
    let func_names: Vec<&str> = funcs
        .iter()
        .filter_map(|f| function_name(f, source))
        .collect();
    if func_names.contains(&"schedule") && func_names.contains(&"execute") {
        return ContractRole::GovernanceTimelock;
    }

    ContractRole::Unknown
}

// ---------------------------------------------------------------------------
// Flash loan receiver detection
// ---------------------------------------------------------------------------

/// Known flash-loan callback function names across major protocols.
///
/// These are entry points *called by the lending pool*, not by end users.
/// They are not traditional attack surface in the same way as public user-facing functions.
const FLASH_LOAN_RECEIVER_NAMES: &[&str] = &[
    "executeOperation",       // Aave V2/V3
    "onFlashLoan",            // ERC-3156 (MakerDAO, Euler, dYdX, EIP-3156)
    "uniswapV3FlashCallback", // Uniswap V3 flash
    "receiveFlashLoan",       // Balancer
    "executeFlashLoan",       // CREAM Finance
    "flashLoanCallback",      // Generic / custom
    "callbackFromFlashLoan",  // Generic
];

/// Returns `true` if `func` is a known flash-loan callback entry point.
///
/// Flash loan callbacks are invoked by trusted pool contracts with specific
/// preconditions (repayment enforced by the pool). They legitimately contain
/// external calls followed by state writes as part of the required protocol flow.
pub fn is_flash_loan_receiver(func: &Node, source: &str) -> bool {
    match function_name(func, source) {
        Some(name) => FLASH_LOAN_RECEIVER_NAMES.contains(&name),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Uniswap callback detection
// ---------------------------------------------------------------------------

/// Known Uniswap and major fork DEX callback function names.
const UNISWAP_CALLBACK_NAMES: &[&str] = &[
    "uniswapV2Call",          // Uniswap V2
    "uniswapV3SwapCallback",  // Uniswap V3 swap
    "uniswapV3MintCallback",  // Uniswap V3 mint
    "uniswapV3BurnCallback",  // Uniswap V3 burn
    "uniswapV3FlashCallback", // Uniswap V3 flash
    "pancakeCall",            // PancakeSwap (V2 fork)
    "sushiswapV2Call",        // SushiSwap
    "algebraSwapCallback",    // Algebra (QuickSwap V3)
];

/// Returns `true` if `func` is a Uniswap-style DEX callback.
///
/// Pool contracts invoke these callbacks during swap/liquidity operations.
/// The caller is a known pool address (validated by the pool's own checks),
/// so the function is not a typical arbitrary-caller entry point.
pub fn is_uniswap_callback(func: &Node, source: &str) -> bool {
    match function_name(func, source) {
        Some(name) => UNISWAP_CALLBACK_NAMES.contains(&name),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// ERC-4626 vault detection
// ---------------------------------------------------------------------------

/// ERC-4626 required function names. Presence of ≥4 signals a vault contract.
const ERC4626_METHODS: &[&str] = &[
    "deposit",
    "mint",
    "withdraw",
    "redeem",
    "totalAssets",
    "convertToShares",
    "convertToAssets",
    "maxDeposit",
    "maxMint",
    "maxWithdraw",
    "maxRedeem",
    "previewDeposit",
    "previewMint",
    "previewWithdraw",
    "previewRedeem",
];

const ERC4626_MIN_MATCH: usize = 4;

/// Returns `true` if the contract(s) in `root` implement ERC-4626 tokenized vaults.
///
/// Matching ≥4 ERC-4626 method names is strong evidence of vault semantics.
/// Vaults legitimately combine external token transfers with share accounting
/// state writes, which can look like reentrancy out of context.
pub fn is_erc4626_vault(root: &Node, source: &str) -> bool {
    let funcs = find_nodes_of_kind(root, "function_definition");
    let matches = funcs
        .iter()
        .filter_map(|f| function_name(f, source))
        .filter(|name| ERC4626_METHODS.contains(name))
        .count();
    matches >= ERC4626_MIN_MATCH
}

// ---------------------------------------------------------------------------
// Proxy upgrade function detection
// ---------------------------------------------------------------------------

/// Known proxy upgrade hook names (EIP-1967 / OpenZeppelin UUPS / Transparent).
const PROXY_UPGRADE_NAMES: &[&str] = &[
    "_authorizeUpgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "upgradeToAndCallWithProof",
    "setImplementation",
    "_setImplementation",
    "_upgradeTo",
    "_upgradeToAndCall",
];

/// Returns `true` if `func` controls the proxy implementation address.
///
/// These functions require strong access control; the storage-collision and
/// access-control detectors should treat them as high-priority targets rather
/// than false-positive candidates.
pub fn is_proxy_upgrade_function(func: &Node, source: &str) -> bool {
    match function_name(func, source) {
        Some(name) => PROXY_UPGRADE_NAMES.contains(&name),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// CEI pattern detection
// ---------------------------------------------------------------------------

/// Returns `true` when the function follows Checks-Effects-Interactions:
/// no state write is reachable after any external call on any execution path.
///
/// Forward taint: ExternalCall → source, StateWrite → sink, no sanitizers.
/// If the CFG produces zero violations, all state writes precede all external calls.
pub fn has_cei_pattern(cfg: &ControlFlowGraph) -> bool {
    let query = TaintQuery {
        sources: vec![CfgStatementKind::ExternalCall],
        sinks: vec![CfgStatementKind::StateWrite],
        sanitizers: vec![],
    };
    find_taint_violations(cfg, &query).is_empty()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::new_solidity_parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = new_solidity_parser().expect("parser");
        parser.parse(source, None).expect("parse")
    }

    #[test]
    fn aave_execute_operation_is_flash_loan_receiver() {
        let src = "pragma solidity ^0.8.0; contract R { function executeOperation(address[] calldata, uint256[] calldata, uint256[] calldata, address, bytes calldata) external returns (bool) {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            funcs.iter().any(|f| is_flash_loan_receiver(f, src)),
            "executeOperation must be detected as flash loan receiver"
        );
    }

    #[test]
    fn erc3156_on_flash_loan_is_flash_loan_receiver() {
        let src = "pragma solidity ^0.8.0; contract R { function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32) {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            funcs.iter().any(|f| is_flash_loan_receiver(f, src)),
            "onFlashLoan must be detected as flash loan receiver"
        );
    }

    #[test]
    fn ordinary_withdraw_is_not_flash_loan_receiver() {
        let src =
            "pragma solidity ^0.8.0; contract C { function withdraw(uint256 amount) external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            !funcs.iter().any(|f| is_flash_loan_receiver(f, src)),
            "withdraw must not be detected as flash loan receiver"
        );
    }

    #[test]
    fn uniswap_v2_call_is_uniswap_callback() {
        let src = "pragma solidity ^0.8.0; contract P { function uniswapV2Call(address, uint, uint, bytes calldata) external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            funcs.iter().any(|f| is_uniswap_callback(f, src)),
            "uniswapV2Call must be detected as Uniswap callback"
        );
    }

    #[test]
    fn uniswap_v3_swap_callback_is_uniswap_callback() {
        let src = "pragma solidity ^0.8.0; contract P { function uniswapV3SwapCallback(int256, int256, bytes calldata) external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            funcs.iter().any(|f| is_uniswap_callback(f, src)),
            "uniswapV3SwapCallback must be detected as Uniswap callback"
        );
    }

    #[test]
    fn erc4626_vault_detected_from_four_methods() {
        let src = r#"pragma solidity ^0.8.0;
contract MyVault {
    function deposit(uint256 assets, address receiver) public returns (uint256) {}
    function mint(uint256 shares, address receiver) public returns (uint256) {}
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) {}
    function redeem(uint256 shares, address receiver, address owner) public returns (uint256) {}
    function totalAssets() public view returns (uint256) {}
}"#;
        let tree = parse(src);
        assert!(
            is_erc4626_vault(&tree.root_node(), src),
            "5 ERC-4626 methods must be detected as vault"
        );
    }

    #[test]
    fn non_vault_not_detected_as_erc4626() {
        let src = r#"pragma solidity ^0.8.0;
contract Token {
    function transfer(address to, uint256 amount) public returns (bool) {}
    function approve(address spender, uint256 amount) public returns (bool) {}
}"#;
        let tree = parse(src);
        assert!(
            !is_erc4626_vault(&tree.root_node(), src),
            "ERC-20 token must not be detected as ERC-4626 vault"
        );
    }

    #[test]
    fn authorize_upgrade_is_proxy_upgrade_function() {
        let src = "pragma solidity ^0.8.0; contract C { function _authorizeUpgrade(address) internal {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(
            funcs.iter().any(|f| is_proxy_upgrade_function(f, src)),
            "_authorizeUpgrade must be detected as proxy upgrade function"
        );
    }

    #[test]
    fn classify_flash_loan_receiver_contract() {
        let src = r#"pragma solidity ^0.8.0;
contract AaveReceiver {
    function executeOperation(address[] calldata, uint256[] calldata, uint256[] calldata, address, bytes calldata) external returns (bool) {
        return true;
    }
}"#;
        let tree = parse(src);
        assert_eq!(
            classify_contract_role(&tree.root_node(), src),
            ContractRole::FlashLoanReceiver
        );
    }

    #[test]
    fn classify_unknown_contract() {
        let src = "pragma solidity ^0.8.0; contract C { function foo() public {} }";
        let tree = parse(src);
        assert_eq!(
            classify_contract_role(&tree.root_node(), src),
            ContractRole::Unknown
        );
    }

    #[test]
    fn classify_timelock_by_name() {
        let src = "pragma solidity ^0.8.0; contract GovernanceTimelock { function queue(bytes32 id) public {} }";
        let tree = parse(src);
        assert_eq!(
            classify_contract_role(&tree.root_node(), src),
            ContractRole::GovernanceTimelock
        );
    }
}
