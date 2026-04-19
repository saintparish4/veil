//! Detector: Unsafe on-chain randomness.
//!
//! Flags `keccak256(abi.encodePacked(block.timestamp, ...))` and `blockhash()`
//! patterns that miners or validators can predict or manipulate.
//! Uses AST to find actual call nodes and member accesses, avoiding false
//! positives from comments and string literals.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, get_call_target, get_member_access, node_text, CallTarget,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct UnsafeRandomDetector;

impl Detector for UnsafeRandomDetector {
    fn id(&self) -> &'static str {
        "unsafe-random"
    }
    fn name(&self) -> &'static str {
        "Unsafe Randomness"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC06:2025 - Unsafe Randomness and Predictability")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            let calls = find_nodes_of_kind(&body, "call_expression");

            let has_bad_randomness = calls.iter().any(|call| {
                match get_call_target(call, ctx.source) {
                    Some(CallTarget::FreeFunction { name: "blockhash" }) => return true,
                    Some(CallTarget::FreeFunction { name: "keccak256" }) => {
                        // Check if args contain block.timestamp/difficulty/number
                        let call_text = node_text(call, ctx.source);
                        let members = find_nodes_of_kind(call, "member_expression")
                            .into_iter()
                            .chain(find_nodes_of_kind(call, "member_access_expression"));
                        for m in members {
                            if let Some(("block", prop)) = get_member_access(&m, ctx.source) {
                                if matches!(
                                    prop,
                                    "timestamp" | "difficulty" | "number" | "prevrandao"
                                ) && call_text.contains("abi.encodePacked")
                                {
                                    return true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                false
            });

            if has_bad_randomness {
                findings.push(Finding::from_detector(
                    self,
                    func.start_position().row + 1,
                    Confidence::Medium,
                    "Unsafe Randomness",
                    "Using block variables for randomness can be predicted/manipulated".to_string(),
                    "Use Chainlink VRF or commit-reveal scheme for secure randomness",
                ));
            }
        }
    }
}
