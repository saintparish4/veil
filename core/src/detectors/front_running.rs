//! Detector: Front-running susceptibility.
//!
//! Flags approval race conditions, missing slippage protection on swaps/withdraws,
//! front-runnable auctions without commit-reveal, unprotected first-come mints,
//! and MEV-attractive liquidation incentives.
//! Uses AST function nodes for scoping and name extraction.

use crate::ast_utils::{func_body, function_name, function_visibility, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct FrontRunningDetector;

impl Detector for FrontRunningDetector {
    fn id(&self) -> &'static str {
        "front-running"
    }
    fn name(&self) -> &'static str {
        "Front-Running Vulnerability"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC09:2025 - Denial of Service (DoS) Attacks")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let visibility = function_visibility(func, ctx.source);
            if !visibility.is_externally_callable() {
                continue;
            }

            let name = function_name(func, ctx.source).unwrap_or("");
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);
            let func_text = node_text(func, ctx.source);
            let line = func.start_position().row + 1;

            // Pattern 1: Token approval without allowance check
            if name.contains("approve") {
                let has_allowance_check = (body_text.contains("allowance(")
                    && (body_text.contains("== 0") || body_text.contains("require(")))
                    || body_text.contains("allowance[")
                    || body_text.contains("allowances[");
                let uses_safe_approve = body_text.contains("increaseAllowance")
                    || body_text.contains("decreaseAllowance");
                let is_direct_approve =
                    body_text.contains("approve(") || body_text.contains("super.approve");

                if is_direct_approve && !has_allowance_check && !uses_safe_approve {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::Medium,
                        "Approval Race Condition",
                        "ERC20 approve vulnerable to front-running".to_string(),
                        "Use increaseAllowance/decreaseAllowance or require current allowance is 0",
                    ));
                }
            }

            // Pattern 2: Swap/Withdraw without slippage protection
            if name.contains("swap") || name.contains("exchange") {
                let has_slippage = func_text.contains("minAmount")
                    || func_text.contains("minOut")
                    || func_text.contains("amountOutMin")
                    || func_text.contains("slippage")
                    || func_text.contains("deadline");

                if !has_slippage {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "Missing Slippage Protection".to_string(),
                        message: "Swap function without minimum output amount".to_string(),
                        suggestion:
                            "Add minAmountOut parameter and deadline for sandwich attack protection"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }

            if name.contains("withdraw")
                && (body_text.contains("getPrice")
                    || body_text.contains("price")
                    || body_text.contains("calculateShares")
                    || body_text.contains("reserve"))
            {
                let has_slippage = func_text.contains("minAmount")
                    || func_text.contains("minOut")
                    || func_text.contains("amountOutMin")
                    || func_text.contains("slippage")
                    || func_text.contains("deadline")
                    || func_text.contains("maxSlippage");

                if !has_slippage {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "Missing Slippage Protection".to_string(),
                        message:
                            "Withdraw function using price calculations without slippage protection"
                                .to_string(),
                        suggestion:
                            "Add minAmountOut parameter and deadline for sandwich attack protection"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }

            // Pattern 3: Auction/bid without commit-reveal
            if name.contains("bid") || name.contains("auction") {
                let has_commit_reveal = body_text.contains("commit")
                    || body_text.contains("reveal")
                    || body_text.contains("hash");

                if !has_commit_reveal && body_text.contains("msg.value") {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::Medium,
                        "Front-Runnable Auction",
                        "Auction bid visible in mempool before execution".to_string(),
                        "Implement commit-reveal scheme for blind bidding",
                    ));
                }
            }

            // Pattern 4: First-come-first-serve without protection
            if name.contains("claim") || name.contains("mint") {
                let has_merkle = body_text.contains("merkle")
                    || body_text.contains("Merkle")
                    || body_text.contains("proof");
                let has_signature = body_text.contains("signature")
                    || body_text.contains("ecrecover")
                    || body_text.contains("ECDSA");
                let has_whitelist =
                    body_text.contains("whitelist") || body_text.contains("allowlist");

                if !has_merkle
                    && !has_signature
                    && !has_whitelist
                    && (body_text.contains("maxSupply") || body_text.contains("limit"))
                {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::Low,
                        line,
                        vulnerability_type: "Front-Runnable Mint".to_string(),
                        message: "First-come-first-serve mint vulnerable to front-running"
                            .to_string(),
                        suggestion: "Consider merkle proof whitelist or signature-based minting"
                            .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }

            // Pattern 5: Liquidation without keeper incentive alignment
            if name.contains("liquidat") {
                let has_incentive = body_text.contains("bonus")
                    || body_text.contains("reward")
                    || body_text.contains("incentive")
                    || body_text.contains("discount");

                if has_incentive {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::Low,
                        line,
                        vulnerability_type: "Liquidation MEV".to_string(),
                        message: "Liquidation with bonus is attractive to MEV searchers"
                            .to_string(),
                        suggestion: "Consider using Flashbots Protect or MEV-aware design"
                            .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }
        }
    }
}
