//! Detector: Reentrancy vulnerabilities.
//!
//! Flags external calls (`.call`, `.transfer`, `.send`) followed by state changes
//! without a reentrancy guard modifier. Uses CFG-based taint when available
//! (sources=ExternalCall, sinks=StateWrite, no sanitizers); falls back to
//! line-number ordering when cfg_for returns None.
//!
//! False-positive suppression:
//! - Flash loan receiver callbacks (`executeOperation`, `onFlashLoan`, etc.) are
//!   skipped — the lending pool enforces repayment atomically; reentrancy by an
//!   external attacker is not the risk model.
//! - Functions with `nonReentrant`/`noReentrancy`/mutex modifiers are skipped.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, function_visibility, has_reentrancy_guard, is_external_call,
    is_state_write,
};
use crate::defi_patterns::is_flash_loan_receiver;
use crate::detector_trait::{AnalysisContext, Detector};
use crate::helpers::visibility_adjusted_confidence;
use crate::taint::{find_taint_violations, CfgStatementKind, TaintQuery};
use crate::types::{Confidence, Finding, Severity};

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }
    fn name(&self) -> &'static str {
        "Reentrancy"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC02:2025 - Reentrancy Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            // Flash loan callbacks are invoked by trusted pool contracts; the pool
            // enforces repayment before returning, so attacker reentrancy is not the
            // risk model. Flagging them produces high-volume false positives on DeFi code.
            if is_flash_loan_receiver(func, ctx.source) {
                continue;
            }

            if has_reentrancy_guard(func, ctx.source) {
                continue;
            }

            let visibility = function_visibility(func, ctx.source);

            // Prefer CFG taint when available (handles branches, early returns, modifier bodies).
            // No Guard sanitizer: a require(ok) after an external call checks return value but
            // does NOT prevent reentrancy — the reentrant call happens *during* the external call,
            // before any post-call guard executes. Only CEI ordering is a real sanitizer here.
            if let Some(cfg_ref) = ctx.cfg_for(func) {
                let query = TaintQuery {
                    sources: vec![CfgStatementKind::ExternalCall],
                    sinks: vec![CfgStatementKind::StateWrite],
                    sanitizers: vec![],
                };
                for v in find_taint_violations(&cfg_ref, &query) {
                    let adjusted = visibility_adjusted_confidence(Confidence::High, visibility);
                    let visibility_note = if !visibility.is_externally_callable() {
                        format!(" ({} function - lower risk)", visibility.as_str())
                    } else {
                        String::new()
                    };
                    findings.push(Finding::from_detector(
                        self,
                        v.source_line,
                        adjusted,
                        "Reentrancy",
                        format!(
                            "External call at line {}, state change at line {}{}",
                            v.source_line, v.sink_line, visibility_note
                        ),
                        "Move state changes before external call, or add nonReentrant modifier",
                    ));
                }
                continue;
            }

            // Fallback: line-number ordering when CFG is not available.
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            let calls = find_nodes_of_kind(&body, "call_expression");
            let mut earliest_external_call_line: Option<usize> = None;

            for call in &calls {
                if is_external_call(call, ctx.source) {
                    let line = call.start_position().row + 1;
                    if earliest_external_call_line.is_none_or(|prev| line < prev) {
                        earliest_external_call_line = Some(line);
                    }
                }
            }

            let call_line = match earliest_external_call_line {
                Some(l) => l,
                None => continue,
            };

            let assignments = find_nodes_of_kind(&body, "assignment_expression");
            let augmented = find_nodes_of_kind(&body, "augmented_assignment_expression");

            let state_change_line = assignments
                .iter()
                .chain(augmented.iter())
                .filter(|node| is_state_write(node))
                .map(|node| node.start_position().row + 1)
                .find(|&line| line > call_line);

            if let Some(change_line) = state_change_line {
                let base_confidence = Confidence::High;
                let adjusted = visibility_adjusted_confidence(base_confidence, visibility);

                let visibility_note = if !visibility.is_externally_callable() {
                    format!(" ({} function - lower risk)", visibility.as_str())
                } else {
                    String::new()
                };

                findings.push(Finding::from_detector(
                    self,
                    call_line,
                    adjusted,
                    "Reentrancy",
                    format!(
                        "External call at line {}, state change at line {}{}",
                        call_line, change_line, visibility_note
                    ),
                    "Move state changes before external call, or add nonReentrant modifier",
                ));
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
        ReentrancyDetector.run(&ctx, &mut findings);
        findings
    }

    #[test]
    fn detects_classic_reentrancy() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) external {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}"#;
        let findings = run(src);
        assert!(
            findings.iter().any(|f| f.detector_id == "reentrancy"),
            "classic call-before-state-write must be flagged; got: {:?}",
            findings
        );
    }

    #[test]
    fn cei_compliant_no_finding() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) external {
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}"#;
        let findings = run(src);
        let reentrancy = findings
            .iter()
            .filter(|f| f.detector_id == "reentrancy")
            .count();
        assert_eq!(
            reentrancy, 0,
            "CEI-compliant function must not be flagged; got: {:?}",
            findings
        );
    }

    #[test]
    fn aave_flash_loan_callback_not_flagged() {
        let src = r#"pragma solidity ^0.8.0;
interface IPool {}
contract AaveReceiver {
    mapping(address => uint256) debt;
    IPool pool;
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == address(pool));
        // arbitrage logic...
        (bool ok,) = address(pool).call("");
        debt[initiator] += amounts[0];
        return true;
    }
}"#;
        let findings = run(src);
        let reentrancy = findings
            .iter()
            .filter(|f| f.detector_id == "reentrancy")
            .count();
        assert_eq!(
            reentrancy, 0,
            "Aave executeOperation callback must not be flagged for reentrancy; got: {:?}",
            findings
        );
    }

    #[test]
    fn erc3156_on_flash_loan_not_flagged() {
        let src = r#"pragma solidity ^0.8.0;
contract MyReceiver {
    address lender;
    mapping(address => uint256) positions;
    function onFlashLoan(
        address initiator, address token, uint256 amount, uint256 fee, bytes calldata data
    ) external returns (bytes32) {
        require(msg.sender == lender);
        (bool ok,) = token.call("");
        positions[initiator] = amount;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}"#;
        let findings = run(src);
        let reentrancy = findings
            .iter()
            .filter(|f| f.detector_id == "reentrancy")
            .count();
        assert_eq!(
            reentrancy, 0,
            "ERC-3156 onFlashLoan callback must not be flagged for reentrancy; got: {:?}",
            findings
        );
    }
}
