//! Detector: Integer overflow / underflow.
//!
//! For Solidity >=0.8: flags arithmetic inside `unchecked { }` blocks.
//! For Solidity <0.8: flags raw arithmetic on uint types without SafeMath.
//! Uses AST pragma nodes for version detection and function-level analysis.

use crate::ast_utils::{find_nodes_of_kind, func_body, has_solidity_gte_0_8, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct IntegerOverflowDetector;

impl Detector for IntegerOverflowDetector {
    fn id(&self) -> &'static str {
        "integer-overflow"
    }
    fn name(&self) -> &'static str {
        "Integer Overflow / Underflow"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC03:2025 - Integer Overflow and Underflow")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let root = ctx.tree.root_node();
        let has_safe_version = has_solidity_gte_0_8(&root, ctx.source);

        // Unchecked blocks bypass safety regardless of Solidity version
        self.find_unchecked_math(ctx, findings);

        if !has_safe_version {
            self.find_unsafe_math(ctx, findings);
        }
    }
}

impl IntegerOverflowDetector {
    fn find_unchecked_math(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        // Look for unchecked_block nodes in the AST
        let unchecked_blocks = find_nodes_of_kind(&ctx.tree.root_node(), "unchecked_block");

        for block in &unchecked_blocks {
            let text = node_text(block, ctx.source);
            let has_arithmetic = text.contains(" + ")
                || text.contains(" - ")
                || text.contains(" * ")
                || text.contains("++")
                || text.contains("--");

            if has_arithmetic {
                findings.push(Finding {
                    id: String::new(),
                    detector_id: self.id().to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    line: block.start_position().row + 1,
                    vulnerability_type: "Unchecked Arithmetic".to_string(),
                    message: "Arithmetic in unchecked block bypasses overflow protection"
                        .to_string(),
                    suggestion: "Ensure overflow/underflow is impossible or add manual checks"
                        .to_string(),
                    remediation: None,
                    owasp_category: self.owasp_category().map(|s| s.to_string()),
                    file: None,
                });
            }
        }

        // Fallback: look for `unchecked {` in function bodies for grammars that
        // don't produce a dedicated unchecked_block node.
        if unchecked_blocks.is_empty() {
            for func in &ctx.functions {
                let body = match func_body(func) {
                    Some(b) => b,
                    None => continue,
                };
                let body_text = node_text(&body, ctx.source);
                if (body_text.contains("unchecked {") || body_text.contains("unchecked{"))
                    && (body_text.contains(" + ")
                        || body_text.contains(" - ")
                        || body_text.contains(" * ")
                        || body_text.contains("++")
                        || body_text.contains("--"))
                {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        line: func.start_position().row + 1,
                        vulnerability_type: "Unchecked Arithmetic".to_string(),
                        message: "Arithmetic in unchecked block bypasses overflow protection"
                            .to_string(),
                        suggestion: "Ensure overflow/underflow is impossible or add manual checks"
                            .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }
        }
    }

    fn find_unsafe_math(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);

            let uses_safemath = body_text.contains(".add(")
                || body_text.contains(".sub(")
                || body_text.contains(".mul(")
                || body_text.contains(".div(");

            if uses_safemath {
                continue;
            }

            let has_unsafe_add = body_text.contains(" += ")
                || (body_text.contains(" + ") && body_text.contains("uint"));
            let has_unsafe_sub = body_text.contains(" -= ")
                || (body_text.contains(" - ") && body_text.contains("uint"));
            let has_unsafe_mul = body_text.contains(" *= ")
                || (body_text.contains(" * ") && body_text.contains("uint"));

            if has_unsafe_add || has_unsafe_sub || has_unsafe_mul {
                findings.push(Finding::from_detector(
                    self,
                    func.start_position().row + 1,
                    Confidence::Medium,
                    "Integer Overflow/Underflow",
                    "Arithmetic operation without SafeMath in Solidity <0.8".to_string(),
                    "Use SafeMath library or upgrade to Solidity >=0.8.0",
                ));
            }
        }
    }
}
