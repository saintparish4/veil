//! Shared helpers for detectors: self-service patterns, visibility, normalization.
//!
//! Functions that duplicate `ast_utils` (e.g. `get_function_visibility`,
//! `has_reentrancy_guard`, `has_access_control`, `has_modifier`,
//! `extract_function_name`) have been removed. Use `ast_utils` for AST-based
//! equivalents.

use crate::types::{Confidence, Visibility};

/// Check if a function name indicates a self-service pattern
pub fn is_self_service_function_name(func_name: &str) -> bool {
    let lower_name = func_name.to_lowercase();
    let self_service_names = [
        "deposit",
        "withdraw",
        "withdrawall",
        "withdrawto",
        "claim",
        "claimreward",
        "claimrewards",
        "claimall",
        "stake",
        "unstake",
        "restake",
        "transfer",
        "approve",
        "transferfrom",
        "mint",
        "burn",
        "redeem",
        "redeemall",
        "exit",
        "leave",
        "emergencywithdraw",
        "harvest",
        "compound",
        "reinvest",
    ];
    self_service_names
        .iter()
        .any(|&name| lower_name.contains(name))
}

/// Check if a function operates only on msg.sender's data
pub fn is_self_service_pattern(func_text: &str) -> bool {
    let has_sender_mapping = func_text.contains("balances[msg.sender]")
        || func_text.contains("_balances[msg.sender]")
        || func_text.contains("deposits[msg.sender]")
        || func_text.contains("stakes[msg.sender]")
        || func_text.contains("rewards[msg.sender]")
        || func_text.contains("userInfo[msg.sender]");
    let transfer_to_sender = func_text.contains("payable(msg.sender)")
        || func_text.contains("msg.sender.call{value")
        || func_text.contains("(msg.sender).transfer(")
        || func_text.contains("safeTransfer(msg.sender");
    let token_to_sender = func_text.contains("transfer(msg.sender,")
        || func_text.contains("_transfer(address(this), msg.sender");
    let has_arbitrary_recipient = func_text.contains("address to,")
        || func_text.contains("address _to,")
        || func_text.contains("address recipient,")
        || func_text.contains("address _recipient,");
    (has_sender_mapping || transfer_to_sender || token_to_sender) && !has_arbitrary_recipient
}

/// Combined check for self-service pattern (name + body analysis)
pub fn should_skip_access_control_warning(func_name: &str, func_text: &str) -> bool {
    is_self_service_function_name(func_name) && is_self_service_pattern(func_text)
}

/// Get confidence level based on visibility (reentrancy)
pub fn visibility_adjusted_confidence(base: Confidence, visibility: Visibility) -> Confidence {
    match (base, visibility) {
        (Confidence::High, Visibility::Private) => Confidence::Low,
        (Confidence::High, Visibility::Internal) => Confidence::Medium,
        (Confidence::Medium, Visibility::Private) => Confidence::Low,
        _ => base,
    }
}

/// Normalize vulnerability type for matching (suppression, baseline)
pub fn normalize_vuln_type(s: &str) -> String {
    s.to_lowercase().replace(['-', '_'], " ")
}
