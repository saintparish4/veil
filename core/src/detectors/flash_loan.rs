//! Detector: Flash loan vulnerability patterns.
//!
//! Flags spot-price calculations without TWAP/Chainlink, single-transaction
//! balance checks in sensitive functions, and unvalidated flash-loan callbacks.
//! Uses AST function nodes to scope analysis and avoid comment/string FPs.

use crate::ast_utils::{func_body, function_name, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct FlashLoanDetector;

impl Detector for FlashLoanDetector {
    fn id(&self) -> &'static str {
        "flash-loan"
    }
    fn name(&self) -> &'static str {
        "Flash Loan Vulnerability"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC07:2025 - Flash Loan Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let name = function_name(func, ctx.source).unwrap_or("");
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);
            let line = func.start_position().row + 1;

            // Pattern 1: Price oracle manipulation
            let uses_spot_price = body_text.contains("getReserves")
                || body_text.contains("balanceOf(address(this))")
                || body_text.contains("token.balanceOf")
                || body_text.contains("pair.getReserves");

            let calculates_price = body_text.contains("price")
                || body_text.contains("rate")
                || body_text.contains("ratio");

            let no_twap = !body_text.contains("TWAP")
                && !body_text.contains("twap")
                && !body_text.contains("oracle")
                && !body_text.contains("Chainlink");

            if uses_spot_price && calculates_price && no_twap {
                findings.push(Finding::from_detector(
                    self,
                    line,
                    Confidence::Medium,
                    "Flash Loan Price Manipulation",
                    "Spot price calculation vulnerable to flash loan manipulation".to_string(),
                    "Use TWAP oracle or Chainlink price feeds instead of spot prices",
                ));
            }

            // Pattern 2: Single-transaction balance checks
            let has_balance_check = body_text.contains("balanceOf")
                && (body_text.contains("require") || body_text.contains("if"));
            let modifies_state = body_text.contains(" = ")
                || body_text.contains("transfer")
                || body_text.contains("mint");

            if has_balance_check && modifies_state && !body_text.contains("flashLoan") {
                let is_sensitive = name.contains("swap")
                    || name.contains("borrow")
                    || name.contains("liquidat")
                    || name.contains("withdraw");

                if is_sensitive {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        line,
                        vulnerability_type: "Flash Loan Susceptible".to_string(),
                        message: format!(
                            "Function '{}' uses balance checks that could be manipulated",
                            name
                        ),
                        suggestion:
                            "Consider adding flash loan guards or using time-weighted values"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }

            // Pattern 3: Callback without validation
            if name.contains("Callback") || name.contains("callback") {
                let validates_caller =
                    body_text.contains("msg.sender ==") || body_text.contains("require(msg.sender");

                if !validates_caller {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::High,
                        "Unvalidated Callback",
                        "Flash loan callback without caller validation".to_string(),
                        "Validate msg.sender is the expected flash loan provider",
                    ));
                }
            }
        }
    }
}
