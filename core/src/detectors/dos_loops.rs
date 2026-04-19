//! Detector: Denial-of-service via unbounded loops.
//!
//! Flags unbounded iteration over dynamic arrays, external calls inside loops,
//! growing arrays, and expensive delete operations in loops.
//!
//! Uses CFG back-edge detection when available: identify back edges, then check if
//! the loop body contains ExternalCall nodes. Falls back to AST-based loop detection
//! (for_statement / while_statement + call_expression, etc.) when cfg_for returns None.

use crate::ast_utils::{
    find_nodes_of_kind, func_body, function_name, function_visibility, get_call_target,
    get_member_access, is_external_call, is_state_write, node_text, CallTarget,
};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};
use tree_sitter::Node;

pub struct DosLoopsDetector;

// ---------------------------------------------------------------------------
// Local AST helpers (loop-specific, not general enough for ast_utils)
// ---------------------------------------------------------------------------

/// Extract the body block from a `for_statement` or `while_statement`.
///
/// Tries the `body` named field first; falls back to the last non-punctuation
/// child (handles grammars that don't expose the field by name).
fn loop_body<'a>(loop_node: &Node<'a>) -> Option<Node<'a>> {
    if let Some(b) = loop_node.child_by_field_name("body") {
        return Some(b);
    }
    let count = loop_node.child_count() as u32;
    for i in (0..count).rev() {
        if let Some(child) = loop_node.child(i) {
            // Skip closing delimiters and keywords
            if !matches!(child.kind(), ")" | ";" | "for" | "while" | "(") {
                return Some(child);
            }
        }
    }
    None
}

/// Return `true` if the loop node contains a `.length` member access,
/// which is the canonical indicator of dynamic-array iteration.
///
/// Scans the whole loop node (including condition) to catch both
/// `arr.length` in the condition and variant spellings.
fn has_length_access(loop_node: &Node, source: &str) -> bool {
    // Check both member_expression and member_access_expression variants
    let members_a = find_nodes_of_kind(loop_node, "member_expression");
    let members_b = find_nodes_of_kind(loop_node, "member_access_expression");
    members_a
        .iter()
        .chain(members_b.iter())
        .any(|m| matches!(get_member_access(m, source), Some((_, "length"))))
}

/// Return `true` if the loop's condition identifiers suggest a bounded iteration
/// (e.g. `maxIterations`, `batchSize`, `limit`, `MAX_*`, `pageSize`).
///
/// Checks identifier nodes within the loop to avoid matching unrelated uses
/// of these names outside the loop in the function body.
fn has_iteration_bound(loop_node: &Node, source: &str) -> bool {
    find_nodes_of_kind(loop_node, "identifier")
        .iter()
        .any(|id| {
            let name = node_text(id, source);
            name == "maxIterations"
                || name == "batchSize"
                || name == "limit"
                || name.starts_with("MAX_")
                || name == "pageSize"
                || name == "max"
        })
}

/// Return `true` if `node` (or a descendant) contains a `delete expr` unary expression.
fn has_delete_expression(node: &Node, source: &str) -> bool {
    find_nodes_of_kind(node, "unary_expression")
        .iter()
        .any(|n| {
            n.child(0)
                .is_some_and(|op| node_text(&op, source) == "delete")
        })
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

impl Detector for DosLoopsDetector {
    fn id(&self) -> &'static str {
        "dos-loops"
    }
    fn name(&self) -> &'static str {
        "Denial of Service via Loops"
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
            let line = func.start_position().row + 1;

            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };

            // --- Pattern 3 (CFG path): External call in loop via back-edge detection ---
            let used_cfg_for_ext_call = if let Some(cfg_ref) = ctx.cfg_for(func) {
                for (tail, head) in cfg_ref.back_edges() {
                    let loop_blocks = cfg_ref.loop_blocks_for_back_edge(tail, head);
                    if cfg_ref.blocks_contain_external_call(&loop_blocks) {
                        findings.push(Finding {
                            id: String::new(),
                            detector_id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            line,
                            vulnerability_type: "External Call in Loop".to_string(),
                            message: "External calls in loop - single failure can revert entire transaction"
                                .to_string(),
                            suggestion: "Use pull-over-push pattern: let users withdraw instead of pushing to them"
                                .to_string(),
                            remediation: None,
                            owasp_category: self.owasp_category().map(|s| s.to_string()),
                            file: None,
                        });
                    }
                }
                true
            } else {
                false
            };

            // --- Patterns 1, 3 (AST fallback), 4: inside loop bodies (AST) ---
            let for_loops = find_nodes_of_kind(&body, "for_statement");
            let while_loops = find_nodes_of_kind(&body, "while_statement");

            for loop_node in for_loops.iter().chain(while_loops.iter()) {
                let search_node = loop_body(loop_node).unwrap_or(*loop_node);

                let loop_calls = find_nodes_of_kind(&search_node, "call_expression");
                let has_external_call = loop_calls.iter().any(|c| is_external_call(c, ctx.source));

                let loop_assigns = find_nodes_of_kind(&search_node, "assignment_expression");
                let loop_aug_assigns =
                    find_nodes_of_kind(&search_node, "augmented_assignment_expression");
                let has_storage_write = loop_assigns
                    .iter()
                    .chain(loop_aug_assigns.iter())
                    .any(|a| is_state_write(a));

                let has_delete = has_delete_expression(&search_node, ctx.source);

                // Pattern 1: Unbounded array iteration
                if has_length_access(loop_node, ctx.source)
                    && !has_iteration_bound(loop_node, ctx.source)
                {
                    let severity = if has_external_call {
                        Severity::High
                    } else if has_storage_write || has_delete {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity,
                        confidence: Confidence::Medium,
                        line,
                        vulnerability_type: "Unbounded Loop".to_string(),
                        message: format!(
                            "Function '{}' has unbounded loop that may exceed gas limit",
                            name
                        ),
                        suggestion: "Add pagination or maximum iteration limit".to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }

                // Pattern 3 (AST fallback): external call in loop only when we didn't use CFG
                if !used_cfg_for_ext_call && has_external_call {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        line,
                        vulnerability_type: "External Call in Loop".to_string(),
                        message:
                            "External calls in loop - single failure can revert entire transaction"
                                .to_string(),
                        suggestion:
                            "Use pull-over-push pattern: let users withdraw instead of pushing to them"
                                .to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }

                // Pattern 4: `delete` expression inside a loop body
                if has_delete {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::Medium,
                        "Expensive Loop Operation",
                        "Delete operations in loop are gas-expensive".to_string(),
                        "Consider swap-and-pop pattern or lazy deletion",
                    ));
                }
            }

            // --- Pattern 2: Push to growing array (anywhere in function body) ---
            //
            // Any `expr.push(...)` call in an externally-callable function may
            // indicate an array that grows without bound and could later be
            // iterated.  Emitted at Low confidence since we cannot confirm
            // the array is ever iterated without inter-function analysis.
            let has_push = find_nodes_of_kind(&body, "call_expression")
                .iter()
                .any(|c| {
                    matches!(
                        get_call_target(c, ctx.source),
                        Some(CallTarget::MemberCall { method, .. }) if method == "push"
                    )
                });

            if has_push {
                findings.push(Finding {
                    id: String::new(),
                    detector_id: self.id().to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    line,
                    vulnerability_type: "Growing Array".to_string(),
                    message: "Array grows unbounded - iteration may exceed gas limit".to_string(),
                    suggestion: "Use mapping instead of array, or implement cleanup mechanism"
                        .to_string(),
                    remediation: None,
                    owasp_category: self.owasp_category().map(|s| s.to_string()),
                    file: None,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector_trait::AnalysisContext;
    use crate::scan::new_solidity_parser;

    fn run(source: &str) -> Vec<Finding> {
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(source, None).expect("parse");
        let ctx = AnalysisContext::new(&tree, source);
        let mut findings = Vec::new();
        DosLoopsDetector.run(&ctx, &mut findings);
        findings
    }

    // -----------------------------------------------------------------------
    // True-positive: AST-based detection should fire
    // -----------------------------------------------------------------------

    #[test]
    fn detects_for_loop_with_length() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address[] public users;
    function distributeRewards() external {
        for (uint i = 0; i < users.length; i++) {
            users[i].call{value: 1}("");
        }
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "External Call in Loop"),
            "expected External Call in Loop finding; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_unbounded_array_loop_medium_severity_for_storage_write() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256[] public vals;
    mapping(uint256 => uint256) public m;
    function update() external {
        for (uint i = 0; i < vals.length; i++) {
            m[i] = vals[i];
        }
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Unbounded Loop"),
            "expected Unbounded Loop; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_growing_array_push() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address[] public holders;
    function register() external {
        holders.push(msg.sender);
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Growing Array"),
            "expected Growing Array; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_delete_in_loop() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256[] public vals;
    function clearAll() external {
        for (uint i = 0; i < vals.length; i++) {
            delete vals[i];
        }
    }
}"#;
        let findings = run(src);
        assert!(
            findings
                .iter()
                .any(|f| f.vulnerability_type == "Expensive Loop Operation"),
            "expected Expensive Loop Operation; got: {:?}",
            findings
                .iter()
                .map(|f| &f.vulnerability_type)
                .collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // True-negative: AST-based detection must NOT fire on safe patterns
    // -----------------------------------------------------------------------

    #[test]
    fn no_finding_for_bounded_loop_with_limit() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address[] public users;
    function distributeRewards(uint256 limit) external {
        for (uint i = 0; i < limit && i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}"#;
        let findings = run(src);
        let unbounded = findings
            .iter()
            .any(|f| f.vulnerability_type == "Unbounded Loop");
        assert!(
            !unbounded,
            "bounded loop with 'limit' identifier must not trigger Unbounded Loop"
        );
    }

    #[test]
    fn no_finding_for_internal_function() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address[] internal users;
    function _distribute() internal {
        for (uint i = 0; i < users.length; i++) {
            users[i].call{value: 1}("");
        }
    }
}"#;
        // Internal functions are not externally callable - should be skipped
        let findings = run(src);
        assert!(
            findings.is_empty(),
            "internal function should produce no findings; got: {:?}",
            findings
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: keyword in comment must NOT trigger (AST ignores comments)
    // -----------------------------------------------------------------------

    #[test]
    fn call_in_comment_does_not_trigger_dos_loop() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address[] public users;
    // NOTE: do NOT use users[i].transfer(..) inside the loop
    function safeDistribute() external {
        uint256 snapshot = users.length;
        require(snapshot <= 10, "too many");
        for (uint i = 0; i < snapshot; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}"#;
        // The comment contains ".transfer" but the actual loop has a real call too.
        // More importantly, the loop has `snapshot` (not .length) as the bound.
        // This test verifies the COMMENT doesn't add phantom nodes.
        let findings = run(src);
        // We do expect an "External Call in Loop" because there IS a transfer in the loop.
        // What we verify is that the comment doesn't create a SECOND or PHANTOM finding.
        let ext_call_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability_type == "External Call in Loop")
            .collect();
        // Should be exactly one finding (from the real call), not two (one from comment)
        assert!(
            ext_call_findings.len() <= 1,
            "comment should not produce extra findings; got {} ext-call findings",
            ext_call_findings.len()
        );
    }

    #[test]
    fn transfer_in_string_literal_does_not_trigger_ext_call_in_loop() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256[] public vals;
    function process() external {
        for (uint i = 0; i < vals.length; i++) {
            string memory s = "addr.transfer(amount)";
            vals[i] = i;
        }
    }
}"#;
        let findings = run(src);
        // String literal ".transfer" must NOT produce External Call in Loop
        let has_ext = findings
            .iter()
            .any(|f| f.vulnerability_type == "External Call in Loop");
        assert!(
            !has_ext,
            "transfer in string literal must not trigger External Call in Loop"
        );
    }
}
