//! Detector: Timestamp dependence.
//!
//! Flags exact equality checks and modulo operations on `block.timestamp`,
//! which can be manipulated by miners within a ~15-second window.
//! Uses AST to find `block.timestamp` member accesses inside binary expressions,
//! avoiding false positives from comments and string literals.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, get_member_access, is_view_or_pure, node_text,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct TimestampDetector;

impl Detector for TimestampDetector {
    fn id(&self) -> &'static str {
        "timestamp-dependence"
    }
    fn name(&self) -> &'static str {
        "Timestamp Dependence"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
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

            let is_view = is_view_or_pure(func, ctx.source);

            // Find all binary expressions containing block.timestamp
            let binary_exprs = find_nodes_of_kind(&body, "binary_expression");
            for expr in &binary_exprs {
                let members = find_nodes_of_kind(expr, "member_expression")
                    .into_iter()
                    .chain(find_nodes_of_kind(expr, "member_access_expression"));

                let has_timestamp = members.into_iter().any(|m| {
                    matches!(
                        get_member_access(&m, ctx.source),
                        Some(("block", "timestamp"))
                    )
                });

                if !has_timestamp {
                    continue;
                }

                let expr_text = node_text(expr, ctx.source);
                let has_equality = expr_text.contains("==")
                    && !expr_text.contains(">=")
                    && !expr_text.contains("<=");
                let has_modulo = expr_text.contains('%');

                if has_equality || has_modulo {
                    let severity = if has_modulo {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    let confidence = if is_view {
                        Confidence::Low
                    } else {
                        Confidence::Medium
                    };
                    let message = if has_modulo {
                        "Using block.timestamp with modulo can be manipulated by miners"
                    } else {
                        "Exact comparison with block.timestamp can be manipulated"
                    };

                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity,
                        confidence,
                        line: func.start_position().row + 1,
                        vulnerability_type: "Timestamp Dependence".to_string(),
                        message: message.to_string(),
                        suggestion:
                            "Use block.timestamp only for >15 minute precision; avoid equality checks"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                    break;
                }
            }
        }
    }
}
