//! Detector: Missing access control on sensitive functions.
//!
//! Flags public/external functions that perform sensitive operations (selfdestruct,
//! delegatecall, ownership changes, etc.) or allow arbitrary fund transfers without
//! access-control modifiers or `require(msg.sender == ...)` checks.
//!
//! Uses CFG taint when available: sources=entry block, sinks=StateWrite/InternalCall(sensitive),
//! sanitizers=Guard — verifies all paths to sensitive operations pass through an access check.
//! Falls back to AST-based sensitive-operation and parameter checks when cfg_for returns None.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, function_name, function_visibility, get_call_target,
    has_access_control, node_text, CallTarget,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::helpers::should_skip_access_control_warning;
use crate::taint::{find_taint_violations, CfgStatementKind, TaintQuery};
use crate::types::{Confidence, Finding, Severity};
use tree_sitter::Node;

pub struct AccessControlDetector;

// ---------------------------------------------------------------------------
// Local AST helpers
// ---------------------------------------------------------------------------

/// Return `true` if `name` is a known sensitive admin/protocol call target.
///
/// This replaces the 16-element `sensitive_keywords` string array that was
/// previously matched with `body_text.to_lowercase().contains(...)`.
/// By matching only call targets, we avoid false positives from comments,
/// string literals, variable names, and event names containing these strings.
fn is_sensitive_call_name(name: &str) -> bool {
    matches!(
        name,
        "selfdestruct"
            | "suicide"
            | "delegatecall"
            | "setOwner"
            | "changeOwner"
            | "transferOwnership"
            | "setAdmin"
            | "addAdmin"
            | "pause"
            | "unpause"
            | "setFee"
            | "setRate"
            | "upgrade"
            | "setImplementation"
            | "initialize"
            | "init"
    )
}

/// Return `true` if the function body contains any call to a sensitive
/// admin/protocol operation.
///
/// Checks both free-function calls (`selfdestruct(...)`) and member calls
/// (`impl.delegatecall(...)`).
fn has_sensitive_operation(body: &Node, source: &str) -> bool {
    find_nodes_of_kind(body, "call_expression")
        .iter()
        .any(|call| {
            let callee = match get_call_target(call, source) {
                Some(CallTarget::FreeFunction { name }) => name,
                Some(CallTarget::MemberCall { method, .. }) => method,
                None => return false,
            };
            is_sensitive_call_name(callee)
        })
}

/// Return `true` if the function signature has a parameter of type `address` (or
/// `address payable`) with a recipient-style name (`to`, `_to`, `recipient`,
/// `_recipient`, `destination`, `receiver`, `_receiver`).
///
/// Replaces `func_text.contains("address to") || func_text.contains("address _to")
/// || func_text.contains("address recipient")` with structural AST inspection.
///
/// Strategy: find every `identifier` node in the function's signature area (before
/// the body), check if its text is a recipient name, then walk siblings within its
/// parent node looking for an `address` / `address payable` type token that
/// precedes the identifier. This is robust to varying tree-sitter grammar node
/// kinds (`parameter`, `variable_declaration`, etc.) across grammar versions.
fn has_address_recipient_param(func_node: &Node, source: &str) -> bool {
    const RECIPIENT_NAMES: &[&str] = &[
        "to",
        "_to",
        "recipient",
        "_recipient",
        "destination",
        "_destination",
        "receiver",
        "_receiver",
    ];

    // Only scan the signature area — identifiers inside the body are irrelevant.
    let body_start = func_body(func_node)
        .map(|b| b.start_byte())
        .unwrap_or(usize::MAX);

    for id_node in find_nodes_of_kind(func_node, "identifier") {
        if id_node.start_byte() >= body_start {
            continue;
        }

        let name = node_text(&id_node, source);
        if !RECIPIENT_NAMES.contains(&name) {
            continue;
        }

        // Recipient-style identifier found in the signature area.
        // Check sibling nodes that appear BEFORE this identifier in its parent —
        // one of them should be the `address` type token.
        let parent = match id_node.parent() {
            Some(p) => p,
            None => continue,
        };

        let id_start = id_node.start_byte();
        let count = parent.child_count() as u32;
        for j in 0..count {
            let sibling = match parent.child(j) {
                Some(s) => s,
                None => continue,
            };
            // Only look at nodes before the identifier.
            if sibling.start_byte() >= id_start {
                break;
            }
            let sib_text = node_text(&sibling, source);
            if sib_text == "address" || sib_text == "address payable" {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

impl Detector for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access-control"
    }
    fn name(&self) -> &'static str {
        "Missing Access Control"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }

    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let visibility = function_visibility(func, ctx.source);
            if !visibility.is_externally_callable() {
                continue;
            }

            let name = match function_name(func, ctx.source) {
                Some(n) => n,
                None => continue,
            };

            // Skip well-known user-facing functions that legitimately have
            // no admin access control by design.
            const PURE_USER_FUNCTIONS: &[&str] = &[
                "stake",
                "unstake",
                "deposit",
                "claim",
                "claimReward",
                "claimRewards",
                "harvest",
                "compound",
                "reinvest",
                "exit",
                "leave",
                "balanceOf",
                "allowance",
                "totalSupply",
                "name",
                "symbol",
                "decimals",
                "getPrice",
                "getShares",
                "getBalance",
                "getReward",
                "earned",
                "getStakerInfo",
                "getContractStats",
                "getTotalReleasableAmount",
            ];

            let name_lower = name.to_lowercase();
            if PURE_USER_FUNCTIONS
                .iter()
                .any(|&puf| name_lower == puf.to_lowercase())
            {
                continue;
            }

            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            let func_text = node_text(func, ctx.source);

            // --- Check 1: Sensitive operation without access control ---
            //
            // CFG path: all paths from entry to StateWrite/InternalCallSensitive must pass a Guard.
            let used_cfg_for_check1 = if let Some(cfg_ref) = ctx.cfg_for(func) {
                let query = TaintQuery {
                    sources: vec![CfgStatementKind::EntryBlock],
                    sinks: vec![
                        CfgStatementKind::StateWrite,
                        CfgStatementKind::InternalCallSensitive,
                    ],
                    sanitizers: vec![CfgStatementKind::Guard],
                };
                for v in find_taint_violations(&cfg_ref, &query) {
                    if should_skip_access_control_warning(name, func_text) {
                        continue;
                    }
                    let line = if v.sink_line > 0 {
                        v.sink_line
                    } else {
                        v.source_line
                    };
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::High,
                        "Missing Access Control",
                        format!(
                            "Function '{}' has path to sensitive operation without access control",
                            name
                        ),
                        "Add onlyOwner, onlyAdmin, or require(msg.sender == ...) guard",
                    ));
                }
                true
            } else {
                false
            };

            // AST fallback for Check 1 when CFG is not available.
            if !used_cfg_for_check1
                && has_sensitive_operation(&body, ctx.source)
                && !has_access_control(func, ctx.source)
            {
                if should_skip_access_control_warning(name, func_text) {
                    continue;
                }

                findings.push(Finding::from_detector(
                    self,
                    func.start_position().row + 1,
                    Confidence::High,
                    "Missing Access Control",
                    format!(
                        "Function '{}' performs sensitive operations without access control",
                        name
                    ),
                    "Add onlyOwner, onlyAdmin, or similar access control modifier",
                ));
            }

            // --- Check 2: Withdraw/transfer function with arbitrary recipient ---
            //
            // Function names that move funds are higher risk when the recipient
            // is an arbitrary caller-supplied address.
            let is_fund_mover = name_lower.contains("withdraw")
                || name_lower.contains("transfer")
                || name_lower.contains("send");

            if is_fund_mover {
                if should_skip_access_control_warning(name, func_text) {
                    continue;
                }

                // Uses AST parameter inspection instead of `func_text.contains("address to")`.
                if has_address_recipient_param(func, ctx.source)
                    && !has_access_control(func, ctx.source)
                {
                    findings.push(Finding::from_detector(
                        self,
                        func.start_position().row + 1,
                        Confidence::High,
                        "Unrestricted Fund Transfer",
                        format!(
                            "Function '{}' allows arbitrary fund transfers without access control",
                            name
                        ),
                        "Add access control or restrict to msg.sender withdrawals only",
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector_trait::AnalysisContext;
    use crate::scan::new_solidity_parser;

    fn run(source: &str) -> Vec<Finding> {
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(source, None).expect("parse");
        let ctx = AnalysisContext::new(&tree, source);
        let mut findings = Vec::new();
        AccessControlDetector.run(&ctx, &mut findings);
        findings
    }

    // -----------------------------------------------------------------------
    // True-positive: detector should fire
    // -----------------------------------------------------------------------

    #[test]
    fn detects_selfdestruct_without_access_control() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Missing Access Control"),
            "expected Missing Access Control for unguarded selfdestruct; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_transfer_with_arbitrary_recipient() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function withdraw(address to) external {
        payable(to).transfer(address(this).balance);
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Unrestricted Fund Transfer"),
            "expected Unrestricted Fund Transfer; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_pause_without_access_control() {
        let src = r#"pragma solidity ^0.8.0;
interface IPausable { function pause() external; }
contract C {
    IPausable token;
    function pauseProtocol() external {
        token.pause();
    }
}"#;
        let findings = run(src);
        // Method call on object: method = "pause" → should trigger
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Missing Access Control"),
            "expected Missing Access Control for unguarded pause(); got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // True-negative: detector must NOT fire on safe patterns
    // -----------------------------------------------------------------------

    #[test]
    fn no_finding_when_onlyowner_modifier_present() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address owner;
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function destroy() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}"#;
        let findings = run(src);
        assert!(
            findings.is_empty(),
            "onlyOwner-guarded selfdestruct must not produce findings; got: {:?}",
            findings
        );
    }

    #[test]
    fn no_finding_for_self_service_withdraw() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}"#;
        let findings = run(src);
        // No arbitrary recipient, no sensitive operation — no finding expected
        let access_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detector_id == "access-control")
            .collect();
        assert!(
            access_findings.is_empty(),
            "self-service withdraw must not flag access control; got: {:?}",
            access_findings
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: keyword in comment must NOT trigger (AST ignores comments)
    // -----------------------------------------------------------------------

    #[test]
    fn selfdestruct_in_comment_does_not_trigger() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    // Previously: selfdestruct(payable(owner)); -- removed for safety
    function adminAction() external onlyOwner {
        owner = address(0);
    }
}"#;
        let findings = run(src);
        let has_ac = findings
            .iter()
            .any(|f| f.vulnerability_type == "Missing Access Control");
        assert!(
            !has_ac,
            "selfdestruct in comment must not trigger Missing Access Control"
        );
    }

    #[test]
    fn selfdestruct_in_string_literal_does_not_trigger() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function getWarning() external pure returns (string memory) {
        return "Do not use selfdestruct on this contract";
    }
}"#;
        let findings = run(src);
        let has_ac = findings
            .iter()
            .any(|f| f.vulnerability_type == "Missing Access Control");
        assert!(
            !has_ac,
            "selfdestruct in string literal must not trigger Missing Access Control"
        );
    }

    #[test]
    fn delegatecall_in_event_name_does_not_trigger_access_control() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    event DelegatecallExecuted(address target);
    function logAction(address target) external {
        emit DelegatecallExecuted(target);
    }
}"#;
        let findings = run(src);
        let has_ac = findings
            .iter()
            .any(|f| f.vulnerability_type == "Missing Access Control");
        assert!(
            !has_ac,
            "delegatecall in event name must not trigger Missing Access Control"
        );
    }

    #[test]
    fn initialize_in_variable_name_does_not_trigger() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    bool public initialized;
    function setup() external {
        initialized = true;
    }
}"#;
        let findings = run(src);
        let has_ac = findings
            .iter()
            .any(|f| f.vulnerability_type == "Missing Access Control");
        assert!(
            !has_ac,
            "variable named 'initialized' must not trigger Missing Access Control"
        );
    }
}
