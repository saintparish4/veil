//! Detector: Unchecked ERC-20 return values.
//!
//! Flags `transfer()`, `transferFrom()`, and `approve()` calls whose boolean
//! return value is silently discarded. Non-reverting tokens (USDT, BNB, etc.)
//! will succeed at the EVM level but return `false`, leading to silent fund loss.
//! Uses AST expression_statement nodes for accurate scoping.

use crate::ast_utils::{find_nodes_of_kind, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct UncheckedErc20Detector;

impl Detector for UncheckedErc20Detector {
    fn id(&self) -> &'static str {
        "unchecked-erc20"
    }
    fn name(&self) -> &'static str {
        "Unchecked ERC-20 Return Values"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC04:2025 - Lack of Input Validation")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let expr_stmts = find_nodes_of_kind(&ctx.tree.root_node(), "expression_statement");
        for stmt in &expr_stmts {
            let text = node_text(stmt, ctx.source);
            let line = stmt.start_position().row + 1;
            let trimmed = text.trim();

            let return_checked = trimmed.starts_with("require")
                || trimmed.starts_with("bool")
                || trimmed.starts_with("if")
                || trimmed.contains("= ");

            // Pattern 1: Unchecked transfer
            if text.contains(".transfer(")
                && !text.contains("safeTransfer")
                && !return_checked
                && !text.contains("payable(")
            {
                findings.push(Finding::from_detector(
                    self,
                    line,
                    Confidence::High,
                    "Unchecked ERC20 Transfer",
                    "ERC20 transfer() return value not checked".to_string(),
                    "Use SafeERC20.safeTransfer() or check return value",
                ));
            }

            // Pattern 2: Unchecked transferFrom
            if text.contains(".transferFrom(")
                && !text.contains("safeTransferFrom")
                && !return_checked
            {
                findings.push(Finding::from_detector(
                    self,
                    line,
                    Confidence::High,
                    "Unchecked ERC20 TransferFrom",
                    "ERC20 transferFrom() return value not checked".to_string(),
                    "Use SafeERC20.safeTransferFrom() or check return value",
                ));
            }

            // Pattern 3: Unchecked approve
            if text.contains(".approve(") && !text.contains("safeApprove") && !return_checked {
                findings.push(Finding {
                    id: String::new(),
                    detector_id: self.id().to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    line,
                    vulnerability_type: "Unchecked ERC20 Approve".to_string(),
                    message: "ERC20 approve() return value not checked".to_string(),
                    suggestion: "Use SafeERC20.safeApprove() or forceApprove()".to_string(),
                    remediation: None,
                    owasp_category: self.owasp_category().map(|s| s.to_string()),
                    file: None,
                });
            }
        }
    }
}
