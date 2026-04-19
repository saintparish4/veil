//! Detector: Dangerous delegatecall.
//!
//! Flags `delegatecall` to user-supplied addresses without access control,
//! which allows arbitrary code execution in the calling contract's context.
//! Uses AST to find actual `.delegatecall(...)` call nodes, avoiding matches
//! in comments, strings, or event names.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, get_call_target, has_access_control, node_text, CallTarget,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct DangerousDelegatecallDetector;

impl Detector for DangerousDelegatecallDetector {
    fn id(&self) -> &'static str {
        "dangerous-delegatecall"
    }
    fn name(&self) -> &'static str {
        "Dangerous Delegatecall"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            let calls = find_nodes_of_kind(&body, "call_expression");
            let has_delegatecall = calls.iter().any(|c| {
                matches!(
                    get_call_target(c, ctx.source),
                    Some(CallTarget::MemberCall {
                        method: "delegatecall",
                        ..
                    })
                )
            });

            if !has_delegatecall {
                continue;
            }

            // Check if target comes from a parameter (address param in signature)
            let func_text = node_text(func, ctx.source);
            let has_address_param = func_text.contains("address ")
                && (func_text.contains("(address ") || func_text.contains(", address "));

            if has_address_param && !has_access_control(func, ctx.source) {
                findings.push(Finding::from_detector(
                    self,
                    func.start_position().row + 1,
                    Confidence::High,
                    "Dangerous Delegatecall",
                    "Delegatecall to user-supplied address without access control".to_string(),
                    "Add strict access control or use a whitelist for delegatecall targets",
                ));
            }
        }
    }
}
