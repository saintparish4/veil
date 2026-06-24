//! Detector: Flash loan vulnerability patterns.
//!
//! Flags spot-price calculations without TWAP/Chainlink, single-transaction
//! balance checks in sensitive functions, and unvalidated flash-loan callbacks.
//! Uses AST function nodes to scope analysis and avoid comment/string FPs.
//!
//! False-positive suppression:
//! - Known flash-loan receiver callbacks (`executeOperation`, `onFlashLoan`, …)
//!   and Uniswap-style DEX callbacks are detected via `defi_patterns` and given
//!   a more nuanced analysis: we check for caller validation using protocol-specific
//!   patterns (e.g. `initiator ==` for Aave, `sender ==` for ERC-3156) in addition
//!   to the generic `msg.sender ==` check.

use crate::ast_utils::{func_body, function_name, node_text};
use crate::defi_patterns::{is_flash_loan_receiver, is_uniswap_callback};
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
                    // I keep confidence Low here because balance-check heuristics fire on
                    // legitimate defensive code too: false-positive rate is meaningful.
                    findings.push(
                        Finding::from_detector(
                            self,
                            line,
                            Confidence::Low,
                            "Flash Loan Susceptible",
                            format!(
                                "Function '{}' uses balance checks that could be manipulated",
                                name
                            ),
                            "Consider adding flash loan guards or using time-weighted values",
                        )
                        .with_severity(Severity::Medium),
                    );
                }
            }

            // Pattern 3: Callback without caller validation
            //
            // We check known flash-loan and Uniswap callbacks separately from generic
            // "Callback"-named functions so we can apply protocol-specific validation
            // patterns and give better remediation advice.
            let is_known_fl_receiver = is_flash_loan_receiver(func, ctx.source);
            let is_known_uniswap_cb = is_uniswap_callback(func, ctx.source);
            let is_generic_callback = !is_known_fl_receiver
                && !is_known_uniswap_cb
                && (name.contains("Callback") || name.contains("callback"));

            if is_known_fl_receiver || is_known_uniswap_cb || is_generic_callback {
                // Protocol-specific caller validation patterns:
                //   Aave:     initiator == address(this)  or  msg.sender == pool
                //   ERC-3156: msg.sender == lender        or  sender ==
                //   Uniswap:  msg.sender == factory/pool  or  require(msg.sender
                let validates_caller = body_text.contains("msg.sender ==")
                    || body_text.contains("require(msg.sender")
                    || body_text.contains("initiator ==")
                    || body_text.contains("== initiator")
                    || body_text.contains("sender ==")
                    || body_text.contains("== address(this)");

                if !validates_caller {
                    // Known protocol callbacks with no validation are High confidence;
                    // generic callbacks are Medium (may use non-obvious patterns).
                    let confidence = if is_known_fl_receiver || is_known_uniswap_cb {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        confidence,
                        "Unvalidated Callback",
                        format!(
                            "Flash loan/DEX callback '{}' without caller validation",
                            name
                        ),
                        "Validate msg.sender is the expected pool/lender address",
                    ));
                }
            }
        }
    }
}
