//! Detector: tx.origin authentication.
//!
//! Flags comparisons against `tx.origin` which are vulnerable to phishing attacks.
//! Uses AST traversal to find `member_expression` nodes matching `tx.origin`
//! inside binary expressions, avoiding false positives from comments/strings.

use crate::ast_utils::{find_nodes_of_kind, get_member_access, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct TxOriginDetector;

impl Detector for TxOriginDetector {
    fn id(&self) -> &'static str {
        "tx-origin"
    }
    fn name(&self) -> &'static str {
        "tx.origin Authentication"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let binary_exprs = find_nodes_of_kind(&ctx.tree.root_node(), "binary_expression");
        for expr in &binary_exprs {
            let text = node_text(expr, ctx.source);
            if !(text.contains("==") || text.contains("!=")) {
                continue;
            }
            let members = find_nodes_of_kind(expr, "member_expression")
                .into_iter()
                .chain(find_nodes_of_kind(expr, "member_access_expression"));
            for m in members {
                if let Some(("tx", "origin")) = get_member_access(&m, ctx.source) {
                    findings.push(Finding::from_detector(
                        self,
                        expr.start_position().row + 1,
                        Confidence::High,
                        "tx.origin Authentication",
                        "Using tx.origin for authorization is vulnerable to phishing attacks"
                            .to_string(),
                        "Use msg.sender instead of tx.origin for authentication checks",
                    ));
                    break;
                }
            }
        }
    }
}
