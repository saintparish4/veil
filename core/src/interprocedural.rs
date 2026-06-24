//! Inter-procedural function summary analysis.
//!
//! Builds a lightweight `FunctionSummary` per function from a single AST walk.
//! Summaries answer intra-file interprocedural questions:
//!   - Does this function (transitively) write storage?
//!   - Does it make external calls?
//!   - Is it view/pure?
//!   - What modifiers does it have?
//!   - What intra-file callees does it invoke?
//!
//! The summary is intentionally **conservative** (may-analysis): a function is
//! marked `may_write_storage = true` if the AST *contains* an assignment that
//! looks like a storage write. This is the same heuristic used by `is_state_write`
//! in `ast_utils.rs`.
//!
//! Transitive closure is computed once over the call graph within the file.
//! Inter-file calls are not resolved (no cross-file analysis yet).

use crate::ast_utils::{
    find_nodes_of_kind, func_body, function_modifiers, function_name, is_external_call,
    is_state_write, is_view_or_pure, node_text,
};
use crate::detector_trait::AnalysisContext;
use std::collections::HashMap;
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Summary type
// ---------------------------------------------------------------------------

/// Lightweight, AST-only summary of a single function's behaviour.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Declared function name (empty for unnamed receive/fallback).
    pub name: String,
    /// Function may write to contract storage (direct write or via intra-file callee).
    pub may_write_storage: bool,
    /// Function may perform an external call (`.call`, `.send`, `.transfer`, etc.).
    pub may_call_external: bool,
    /// Function is declared `view` or `pure` (no storage writes expected).
    pub is_view_or_pure: bool,
    /// Modifiers applied to the function.
    pub modifiers: Vec<String>,
    /// Names of intra-file callees (identifiers seen in call_expression positions).
    pub calls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build summaries for all `function_definition` nodes in `ctx`.
///
/// Returns a map from function name to summary. If two functions share a name
/// (overloading), the last one wins (rare in practice; summaries are conservative).
pub fn build_summaries(ctx: &AnalysisContext) -> HashMap<String, FunctionSummary> {
    // Pass 1: build direct summaries from the AST.
    let mut direct: HashMap<String, FunctionSummary> = HashMap::new();
    for func in &ctx.functions {
        let summary = summarize_function(func, ctx.source);
        direct.insert(summary.name.clone(), summary);
    }

    // Pass 2: transitive closure over intra-file calls.
    // Propagate may_write_storage and may_call_external through the call graph.
    propagate_transitive(&mut direct);

    direct
}

// ---------------------------------------------------------------------------
// Per-function AST summary
// ---------------------------------------------------------------------------

fn summarize_function(func: &Node, source: &str) -> FunctionSummary {
    let name = function_name(func, source)
        .unwrap_or("")
        .to_string();

    let modifiers = function_modifiers(func, source)
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let view_or_pure = is_view_or_pure(func, source);

    let body = match func_body(func) {
        Some(b) => b,
        None => {
            return FunctionSummary {
                name,
                may_write_storage: false,
                may_call_external: false,
                is_view_or_pure: view_or_pure,
                modifiers,
                calls: Vec::new(),
            }
        }
    };

    // Direct storage writes: assignment_expression and augmented_assignment_expression.
    let assignments = find_nodes_of_kind(&body, "assignment_expression");
    let augmented = find_nodes_of_kind(&body, "augmented_assignment_expression");
    let may_write_storage = assignments
        .iter()
        .chain(augmented.iter())
        .any(|n| is_state_write(n));

    // External calls.
    let call_exprs = find_nodes_of_kind(&body, "call_expression");
    let may_call_external = call_exprs.iter().any(|n| is_external_call(n, source));

    // Intra-file callees: collect all identifiers in call-target positions.
    let calls = collect_callee_names(&call_exprs, source);

    FunctionSummary {
        name,
        may_write_storage,
        may_call_external,
        is_view_or_pure: view_or_pure,
        modifiers,
        calls,
    }
}

/// Collect function names that appear as call targets (free-function calls).
///
/// For `foo(...)` we capture `foo`; for `addr.foo(...)` we skip (member call to external object).
/// tree-sitter-solidity 1.x wraps the callee in an `expression` node:
///   call_expression → expression → identifier (for free calls)
///   call_expression → expression → member_expression (for object calls, skip)
fn collect_callee_names(call_exprs: &[Node], source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for call in call_exprs {
        // First child of call_expression is the callee (possibly wrapped in `expression`).
        let raw_callee = match call.child(0) {
            Some(c) => c,
            None => continue,
        };
        // Unwrap single `expression` wrapper if present.
        let callee = if raw_callee.kind() == "expression" {
            match raw_callee.child(0) {
                Some(c) => c,
                None => continue,
            }
        } else {
            raw_callee
        };

        if callee.kind() == "identifier" {
            names.push(node_text(&callee, source).to_string());
        }
        // member_expression (e.g. `addr.call`, `token.transfer`) → skip (external)
        // type_cast_expression (e.g. `uint256(x)`) → skip
    }
    names.sort();
    names.dedup();
    names
}

// ---------------------------------------------------------------------------
// Transitive propagation
// ---------------------------------------------------------------------------

/// BFS/Kahn-style transitive propagation.
///
/// Iterates until no more changes propagate. Handles cycles conservatively
/// (taint is sticky once set; cycles don't cause infinite loops).
fn propagate_transitive(summaries: &mut HashMap<String, FunctionSummary>) {
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 50 {
        changed = false;
        iterations += 1;
        // Collect propagation to avoid borrow-checker conflicts.
        let updates: Vec<(String, bool, bool)> = summaries
            .iter()
            .map(|(name, s)| {
                let (mut writes, mut calls_ext) = (s.may_write_storage, s.may_call_external);
                for callee_name in &s.calls {
                    if let Some(callee_summary) = summaries.get(callee_name.as_str()) {
                        writes |= callee_summary.may_write_storage;
                        calls_ext |= callee_summary.may_call_external;
                    }
                }
                (name.clone(), writes, calls_ext)
            })
            .collect();
        for (name, writes, calls_ext) in updates {
            if let Some(s) = summaries.get_mut(&name) {
                if s.may_write_storage != writes || s.may_call_external != calls_ext {
                    s.may_write_storage = writes;
                    s.may_call_external = calls_ext;
                    changed = true;
                }
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

    fn summaries_for(source: &str) -> HashMap<String, FunctionSummary> {
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(source, None).expect("parse");
        let ctx = AnalysisContext::new(&tree, source);
        build_summaries(&ctx)
    }

    #[test]
    fn view_function_no_writes() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256 public value;
    function getValue() external view returns (uint256) { return value; }
}"#;
        let sums = summaries_for(src);
        let s = sums.get("getValue").expect("summary exists");
        assert!(s.is_view_or_pure);
        assert!(!s.may_write_storage);
        assert!(!s.may_call_external);
    }

    #[test]
    fn setter_may_write_storage() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256 public value;
    function setValue(uint256 v) external { value = v; }
}"#;
        let sums = summaries_for(src);
        let s = sums.get("setValue").expect("summary exists");
        assert!(s.may_write_storage);
        assert!(!s.may_call_external);
    }

    #[test]
    fn external_call_detected() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function forward(address payable to) external {
        (bool ok,) = to.call{value: 1}("");
        require(ok);
    }
}"#;
        let sums = summaries_for(src);
        let s = sums.get("forward").expect("summary exists");
        assert!(s.may_call_external);
    }

    #[test]
    fn modifiers_captured() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    modifier onlyOwner() { _; }
    function admin() external onlyOwner {}
}"#;
        let sums = summaries_for(src);
        let s = sums.get("admin").expect("summary exists");
        assert!(s.modifiers.contains(&"onlyOwner".to_string()));
    }

    #[test]
    fn transitive_write_propagates() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256 public counter;
    function increment() internal { counter += 1; }
    function doIncrement() external { increment(); }
}"#;
        let sums = summaries_for(src);
        // increment directly writes storage
        assert!(sums["increment"].may_write_storage);
        // doIncrement calls increment → should propagate
        assert!(
            sums["doIncrement"].may_write_storage,
            "transitive write not propagated"
        );
    }

    #[test]
    fn pure_function_no_state() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b; }
}"#;
        let sums = summaries_for(src);
        let s = sums.get("add").expect("summary exists");
        assert!(s.is_view_or_pure);
        assert!(!s.may_write_storage);
        assert!(!s.may_call_external);
    }
}
