//! Detector: Unchecked external call return values.
//!
//! Flags external calls whose return value is not checked on any path to function exit.
//! Uses CFG taint when available (sources=ExternalCall, sinks=Return/exit block, sanitizers=Guard);
//! falls back to AST heuristic when cfg_for returns None.

use crate::ast_utils::{find_nodes_of_kind, is_external_call, is_inside_node_of_kind, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::taint::{find_taint_violations, CfgStatementKind, TaintQuery};
use crate::types::{Confidence, Finding, Severity};

pub struct UncheckedCallsDetector;

impl Detector for UncheckedCallsDetector {
    fn id(&self) -> &'static str {
        "unchecked-calls"
    }
    fn name(&self) -> &'static str {
        "Unchecked External Call Return Values"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC04:2025 - Lack of Input Validation")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            if let Some(cfg_ref) = ctx.cfg_for(func) {
                let query = TaintQuery {
                    sources: vec![CfgStatementKind::ExternalCall],
                    sinks: vec![CfgStatementKind::Return, CfgStatementKind::ExitBlock],
                    sanitizers: vec![CfgStatementKind::Guard],
                };
                for v in find_taint_violations(&cfg_ref, &query) {
                    let line = if v.sink_line > 0 {
                        v.sink_line
                    } else {
                        v.source_line
                    };
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::High,
                        "Unchecked Call",
                        "External call return value is not checked on path to exit".to_string(),
                        "Check the return value: (bool success, ) = addr.call(...); require(success);",
                    ));
                }
                continue;
            }

            // Fallback: AST-based expression_statement scan for this function when CFG is not available.
            let expr_stmts = find_nodes_of_kind(func, "expression_statement");
            for stmt in &expr_stmts {
                let calls = find_nodes_of_kind(stmt, "call_expression");
                for call in &calls {
                    if !is_external_call(call, ctx.source) {
                        continue;
                    }
                    if is_inside_node_of_kind(call, "assignment_expression")
                        || is_inside_node_of_kind(call, "variable_declaration_statement")
                        || is_inside_node_of_kind(call, "variable_declaration")
                    {
                        continue;
                    }
                    let text = node_text(stmt, ctx.source).trim().to_string();
                    if text.starts_with("(bool") || text.starts_with("bool") || text.contains("= ")
                    {
                        continue;
                    }
                    findings.push(Finding::from_detector(
                        self,
                        stmt.start_position().row + 1,
                        Confidence::High,
                        "Unchecked Call",
                        "External call return value is not checked".to_string(),
                        "Check the return value: (bool success, ) = addr.call(...); require(success);",
                    ));
                    break;
                }
            }
        }
    }
}
