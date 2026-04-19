//! Reusable tree-sitter AST helpers for Solidity analysis.
//!
//! Centralises node traversal, member-access extraction, call-target
//! resolution, visibility reading, and modifier listing so that detectors
//! focus on vulnerability logic rather than tree-sitter plumbing.

use crate::types::Visibility;
use tree_sitter::Node;

/// Shorthand: child count as `u32` (tree-sitter uses `u32` indices).
#[inline]
fn child_count(node: &Node) -> u32 {
    node.child_count() as u32
}

// ---------------------------------------------------------------------------
// Generic tree walking
// ---------------------------------------------------------------------------

/// Collect every descendant of `root` whose `kind()` equals `kind`.
pub fn find_nodes_of_kind<'a>(root: &Node<'a>, kind: &str) -> Vec<Node<'a>> {
    let mut results = Vec::new();
    collect_nodes_of_kind(root, kind, &mut results);
    results
}

fn collect_nodes_of_kind<'a>(node: &Node<'a>, kind: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == kind {
        out.push(*node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_nodes_of_kind(&child, kind, out);
    }
}

/// Return the text slice that `node` spans in `source`.
pub fn node_text<'a>(node: &Node, source: &'a str) -> &'a str {
    &source[node.start_byte()..node.end_byte()]
}

/// Walk ancestors of `node` until one matches `kind`, or return `None`.
pub fn find_ancestor_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == kind {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// Check whether `node` has an ancestor whose kind matches `kind`.
pub fn is_inside_node_of_kind(node: &Node, kind: &str) -> bool {
    find_ancestor_of_kind(node, kind).is_some()
}

// ---------------------------------------------------------------------------
// Member-access helpers  (e.g. `tx.origin`, `block.timestamp`)
// ---------------------------------------------------------------------------

/// For a member-access node, return `(object_text, member_text)`.
/// Returns `None` if the node is not a member access or fields are missing.
pub fn get_member_access<'a>(node: &Node, source: &'a str) -> Option<(&'a str, &'a str)> {
    if node.kind() != "member_expression" && node.kind() != "member_access_expression" {
        return None;
    }
    let object = node.child(0)?;
    let last_idx = child_count(node).checked_sub(1)?;
    let member = node.child(last_idx)?;
    Some((node_text(&object, source), node_text(&member, source)))
}

// ---------------------------------------------------------------------------
// Function-level helpers
// ---------------------------------------------------------------------------

/// Extract the function name from a `function_definition` node using the tree.
pub fn function_name<'a>(func_node: &Node, source: &'a str) -> Option<&'a str> {
    if func_node.kind() != "function_definition" {
        return None;
    }
    if let Some(name_node) = func_node.child_by_field_name("name") {
        return Some(node_text(&name_node, source));
    }
    for i in 0..child_count(func_node) {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "identifier" {
                return Some(node_text(&child, source));
            }
        }
    }
    None
}

/// Read the `visibility` keyword from a `function_definition` node.
pub fn function_visibility(func_node: &Node, source: &str) -> Visibility {
    if func_node.kind() != "function_definition" {
        return Visibility::Public;
    }
    for i in 0..child_count(func_node) {
        if let Some(child) = func_node.child(i) {
            let kind = child.kind();
            if kind == "visibility"
                || kind == "public"
                || kind == "external"
                || kind == "internal"
                || kind == "private"
            {
                let text = node_text(&child, source);
                return match text {
                    "private" => Visibility::Private,
                    "internal" => Visibility::Internal,
                    "external" => Visibility::External,
                    "public" => Visibility::Public,
                    _ => Visibility::Public,
                };
            }
        }
    }
    Visibility::Public
}

/// Check whether the function has a `view` or `pure` state mutability keyword.
pub fn is_view_or_pure(func_node: &Node, source: &str) -> bool {
    if func_node.kind() != "function_definition" {
        return false;
    }
    for i in 0..child_count(func_node) {
        if let Some(child) = func_node.child(i) {
            let kind = child.kind();
            if kind == "state_mutability" || kind == "view" || kind == "pure" {
                let text = node_text(&child, source);
                if text == "view" || text == "pure" {
                    return true;
                }
            }
        }
    }
    false
}

/// Collect modifier names (from `modifier_invocation` children) on a function.
pub fn function_modifiers<'a>(func_node: &Node, source: &'a str) -> Vec<&'a str> {
    let mut mods = Vec::new();
    if func_node.kind() != "function_definition" {
        return mods;
    }
    for i in 0..child_count(func_node) {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "modifier_invocation" {
                if let Some(name_node) = child.child(0) {
                    mods.push(node_text(&name_node, source));
                }
            }
        }
    }
    mods
}

/// Check if a function has any of the given modifier names.
pub fn has_modifier(func_node: &Node, source: &str, names: &[&str]) -> bool {
    let mods = function_modifiers(func_node, source);
    mods.iter().any(|m| names.contains(m))
}

/// Check for common reentrancy guard modifiers on a function node.
pub fn has_reentrancy_guard(func_node: &Node, source: &str) -> bool {
    has_modifier(
        func_node,
        source,
        &["nonReentrant", "noReentrant", "reentrancyGuard", "lock"],
    )
}

/// Check for common access-control modifiers on a function node.
///
/// Matches any modifier starting with `"only"` (e.g. `onlyOwner`, `onlyAdmin`,
/// `onlyMinter`), plus `"whenNotPaused"` and `"initializer"`.
pub fn has_access_control_modifier(func_node: &Node, source: &str) -> bool {
    let mods = function_modifiers(func_node, source);
    mods.iter()
        .any(|m| m.starts_with("only") || *m == "whenNotPaused" || *m == "initializer")
}

/// Check if a function body contains a `require(msg.sender == ...)` pattern,
/// a `hasRole(..., msg.sender)` call, or an `if (msg.sender != ...) revert`
/// pattern by walking the AST.
pub fn has_require_sender_check(func_node: &Node, source: &str) -> bool {
    let body = match func_body(func_node) {
        Some(b) => b,
        None => return false,
    };
    let calls = find_nodes_of_kind(&body, "call_expression");
    for call in &calls {
        let text = node_text(call, source);
        if (text.starts_with("require") || text.starts_with("revert"))
            && text.contains("msg.sender")
        {
            return true;
        }
        // hasRole(..., msg.sender) or similar role-check pattern
        if text.contains("hasRole") && text.contains("msg.sender") {
            return true;
        }
    }
    let ifs = find_nodes_of_kind(&body, "if_statement");
    for if_node in &ifs {
        let has_sender_cond = (0..child_count(if_node)).any(|i| {
            if_node.child(i).is_some_and(|c| {
                c.kind() == "expression" && node_text(&c, source).contains("msg.sender")
            })
        });
        if has_sender_cond {
            if !find_nodes_of_kind(if_node, "revert_statement").is_empty() {
                return true;
            }
            let text = node_text(if_node, source);
            if text.contains("revert") {
                return true;
            }
        }
    }
    false
}

/// Combined access control check: modifier OR require/revert in body.
pub fn has_access_control(func_node: &Node, source: &str) -> bool {
    has_access_control_modifier(func_node, source) || has_require_sender_check(func_node, source)
}

/// Get the function body block node.
pub fn func_body<'a>(func_node: &Node<'a>) -> Option<Node<'a>> {
    if func_node.kind() != "function_definition" {
        return None;
    }
    func_node.child_by_field_name("body").or_else(|| {
        for i in 0..child_count(func_node) {
            if let Some(child) = func_node.child(i) {
                let k = child.kind();
                if k == "function_body"
                    || k == "block"
                    || k == "statement_block"
                    || k == "block_statement"
                {
                    return Some(child);
                }
            }
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Call target resolution
// ---------------------------------------------------------------------------

/// Describes the target of a function call.
#[derive(Debug, Clone, PartialEq)]
pub enum CallTarget<'a> {
    /// `addr.call{...}(...)` / `addr.transfer(...)` / `addr.delegatecall(...)`
    MemberCall { object: &'a str, method: &'a str },
    /// `require(...)`, `keccak256(...)`, etc.
    FreeFunction { name: &'a str },
}

/// Drill through tree-sitter wrapper nodes (`expression`, `struct_expression`)
/// to reach the actual callee node underneath a `call_expression`.
fn unwrap_callee<'a>(node: Node<'a>) -> Node<'a> {
    let mut current = node;
    loop {
        match current.kind() {
            // Grammar wraps callees in generic `expression` nodes
            "expression" => {
                if let Some(child) = current.child(0) {
                    current = child;
                } else {
                    break;
                }
            }
            // `addr.call{value: 1}(...)` wraps the member expr in struct_expression
            "struct_expression" => {
                if let Some(child) = current.child(0) {
                    current = child;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    current
}

/// Resolve the target of a `call_expression` (or `function_call`) node.
pub fn get_call_target<'a>(node: &Node<'a>, source: &'a str) -> Option<CallTarget<'a>> {
    let kind = node.kind();
    if kind != "call_expression" && kind != "function_call" {
        return None;
    }
    let raw_callee = node.child(0)?;
    let callee = unwrap_callee(raw_callee);
    if callee.kind() == "member_expression" || callee.kind() == "member_access_expression" {
        let (obj, method) = get_member_access(&callee, source)?;
        Some(CallTarget::MemberCall {
            object: obj,
            method,
        })
    } else {
        let name = node_text(&callee, source);
        Some(CallTarget::FreeFunction { name })
    }
}

/// Check whether a call_expression is an external call (`.call`, `.transfer`, `.send`,
/// `.delegatecall`, `.staticcall`).
pub fn is_external_call(node: &Node, source: &str) -> bool {
    matches!(get_call_target(node, source), Some(CallTarget::MemberCall { method, .. })
        if matches!(method, "call" | "transfer" | "send" | "delegatecall" | "staticcall"))
}

/// Check whether a node is a state write (`assignment_expression` or
/// `augmented_assignment_expression` that is NOT a local variable declaration).
pub fn is_state_write(node: &Node) -> bool {
    let kind = node.kind();
    if kind == "assignment_expression" || kind == "augmented_assignment_expression" {
        if is_inside_node_of_kind(node, "variable_declaration")
            || is_inside_node_of_kind(node, "variable_declaration_statement")
        {
            return false;
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Pragma / version helpers
// ---------------------------------------------------------------------------

/// Check if any `pragma_directive` declares Solidity ≥0.8.
pub fn has_solidity_gte_0_8(root: &Node, source: &str) -> bool {
    let pragmas = find_nodes_of_kind(root, "pragma_directive");
    for pragma in &pragmas {
        let text = node_text(pragma, source);
        if text.contains("solidity")
            && (text.contains("^0.8")
                || text.contains(">=0.8")
                || text.contains(">0.7")
                || text.contains("0.8."))
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Contract-level helpers
// ---------------------------------------------------------------------------

/// Check if the source indicates this is a proxy / upgradeable contract.
pub fn is_proxy_contract(root: &Node, source: &str) -> bool {
    let contracts = find_nodes_of_kind(root, "contract_declaration");
    for c in &contracts {
        let text = node_text(c, source);
        if text.contains("Upgradeable")
            || text.contains("Proxy")
            || text.contains("UUPS")
            || text.contains("Transparent")
        {
            return true;
        }
    }
    source.contains("delegatecall") || source.contains("implementation")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::scan::new_solidity_parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = new_solidity_parser().expect("parser");
        parser.parse(source, None).expect("parse")
    }

    // ===================================================================
    // find_nodes_of_kind
    // ===================================================================

    #[test]
    fn find_nodes_of_kind_finds_functions() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  function foo() public {}\n  function bar() external {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(funcs.len(), 2);
    }

    #[test]
    fn find_nodes_of_kind_returns_empty_when_no_match() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(funcs.is_empty());
    }

    #[test]
    fn find_nodes_of_kind_nested_contracts() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function a() public {} }\ncontract B { function b() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(funcs.len(), 2);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert_eq!(contracts.len(), 2);
    }

    // ===================================================================
    // node_text
    // ===================================================================

    #[test]
    fn node_text_returns_correct_slice() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  function foo() public {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(funcs.len(), 1);
        let text = node_text(&funcs[0], src);
        assert!(text.contains("function foo()"));
    }

    // ===================================================================
    // find_ancestor_of_kind / is_inside_node_of_kind
    // ===================================================================

    #[test]
    fn find_ancestor_of_kind_finds_contract() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  function foo() public {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let ancestor = find_ancestor_of_kind(&funcs[0], "contract_declaration");
        assert!(ancestor.is_some());
        let text = node_text(&ancestor.unwrap(), src);
        assert!(text.contains("contract A"));
    }

    #[test]
    fn find_ancestor_of_kind_returns_none_for_root() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function foo() public {} }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        let ancestor = find_ancestor_of_kind(&contracts[0], "function_definition");
        assert!(ancestor.is_none());
    }

    #[test]
    fn is_inside_node_of_kind_positive() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function foo() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(is_inside_node_of_kind(&funcs[0], "contract_declaration"));
    }

    #[test]
    fn is_inside_node_of_kind_negative() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function foo() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!is_inside_node_of_kind(&funcs[0], "if_statement"));
    }

    // ===================================================================
    // get_member_access
    // ===================================================================

    #[test]
    fn get_member_access_tx_origin() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  function f() public { require(tx.origin == msg.sender); }\n}";
        let tree = parse(src);
        let members = find_nodes_of_kind(&tree.root_node(), "member_expression")
            .into_iter()
            .chain(find_nodes_of_kind(
                &tree.root_node(),
                "member_access_expression",
            ))
            .collect::<Vec<_>>();
        let found = members.iter().any(|m| {
            if let Some((obj, member)) = get_member_access(m, src) {
                obj == "tx" && member == "origin"
            } else {
                false
            }
        });
        assert!(found, "expected to find tx.origin member access");
    }

    #[test]
    fn get_member_access_returns_none_for_non_member() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(get_member_access(&funcs[0], src).is_none());
    }

    #[test]
    fn get_member_access_block_timestamp() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  function f() public view returns (uint) { return block.timestamp; }\n}";
        let tree = parse(src);
        let members = find_nodes_of_kind(&tree.root_node(), "member_expression")
            .into_iter()
            .chain(find_nodes_of_kind(
                &tree.root_node(),
                "member_access_expression",
            ))
            .collect::<Vec<_>>();
        let found = members
            .iter()
            .any(|m| matches!(get_member_access(m, src), Some(("block", "timestamp"))));
        assert!(found, "expected to find block.timestamp member access");
    }

    // ===================================================================
    // function_name
    // ===================================================================

    #[test]
    fn function_name_extracts_name() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function myFunc() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_name(&funcs[0], src), Some("myFunc"));
    }

    #[test]
    fn function_name_returns_none_for_non_function() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert!(function_name(&contracts[0], src).is_none());
    }

    #[test]
    fn function_name_with_parameters() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function transfer(address to, uint256 amount) external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_name(&funcs[0], src), Some("transfer"));
    }

    // ===================================================================
    // function_visibility
    // ===================================================================

    #[test]
    fn function_visibility_public() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_visibility(&funcs[0], src), Visibility::Public);
    }

    #[test]
    fn function_visibility_external() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_visibility(&funcs[0], src), Visibility::External);
    }

    #[test]
    fn function_visibility_internal() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() internal {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_visibility(&funcs[0], src), Visibility::Internal);
    }

    #[test]
    fn function_visibility_private() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() private {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_visibility(&funcs[0], src), Visibility::Private);
    }

    #[test]
    fn function_visibility_defaults_to_public() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert_eq!(function_visibility(&funcs[0], src), Visibility::Public);
    }

    #[test]
    fn function_visibility_on_non_function_returns_public() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert_eq!(function_visibility(&contracts[0], src), Visibility::Public);
    }

    // ===================================================================
    // is_view_or_pure
    // ===================================================================

    #[test]
    fn is_view_or_pure_view() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public view returns (uint) { return 1; } }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(is_view_or_pure(&funcs[0], src));
    }

    #[test]
    fn is_view_or_pure_pure() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f(uint a) public pure returns (uint) { return a + 1; } }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(is_view_or_pure(&funcs[0], src));
    }

    #[test]
    fn is_view_or_pure_mutable() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public { x = 1; } }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!is_view_or_pure(&funcs[0], src));
    }

    #[test]
    fn is_view_or_pure_non_function() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert!(!is_view_or_pure(&contracts[0], src));
    }

    // ===================================================================
    // function_modifiers / has_modifier
    // ===================================================================

    #[test]
    fn function_modifiers_lists_modifiers() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier onlyOwner() { _; }\n  function f() public onlyOwner {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        let mods = function_modifiers(target, src);
        assert!(mods.contains(&"onlyOwner"), "got: {:?}", mods);
    }

    #[test]
    fn function_modifiers_empty_when_none() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let mods = function_modifiers(&funcs[0], src);
        assert!(mods.is_empty());
    }

    #[test]
    fn has_modifier_positive() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier nonReentrant() { _; }\n  function f() public nonReentrant {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_modifier(target, src, &["nonReentrant"]));
    }

    #[test]
    fn has_modifier_negative() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!has_modifier(&funcs[0], src, &["nonReentrant"]));
    }

    #[test]
    fn function_modifiers_non_function_returns_empty() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert!(function_modifiers(&contracts[0], src).is_empty());
    }

    // ===================================================================
    // has_reentrancy_guard
    // ===================================================================

    #[test]
    fn has_reentrancy_guard_positive() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier nonReentrant() { _; }\n  function f() external nonReentrant {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_reentrancy_guard(target, src));
    }

    #[test]
    fn has_reentrancy_guard_negative() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!has_reentrancy_guard(&funcs[0], src));
    }

    #[test]
    fn has_reentrancy_guard_lock_variant() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier lock() { _; }\n  function f() external lock {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_reentrancy_guard(target, src));
    }

    // ===================================================================
    // has_access_control_modifier
    // ===================================================================

    #[test]
    fn has_access_control_modifier_positive() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier onlyOwner() { _; }\n  function f() external onlyOwner {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_access_control_modifier(target, src));
    }

    #[test]
    fn has_access_control_modifier_negative() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() external {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!has_access_control_modifier(&funcs[0], src));
    }

    #[test]
    fn has_access_control_modifier_only_admin() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier onlyAdmin() { _; }\n  function f() external onlyAdmin {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_access_control_modifier(target, src));
    }

    // ===================================================================
    // has_require_sender_check
    // ===================================================================

    #[test]
    fn has_require_sender_check_positive() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    address owner;
    function f() public {
        require(msg.sender == owner, "not owner");
    }
}"#;
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(has_require_sender_check(&funcs[0], src));
    }

    #[test]
    fn has_require_sender_check_negative() {
        let src =
            "pragma solidity ^0.8.0;\ncontract A {\n  function f() public { uint256 x = 1; }\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!has_require_sender_check(&funcs[0], src));
    }

    #[test]
    fn has_require_sender_check_if_revert_pattern() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    address owner;
    function f() public {
        if (msg.sender != owner) revert("unauthorized");
    }
}"#;
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(has_require_sender_check(&funcs[0], src));
    }

    // ===================================================================
    // has_access_control (combined)
    // ===================================================================

    #[test]
    fn has_access_control_via_modifier() {
        let src = "pragma solidity ^0.8.0;\ncontract A {\n  modifier onlyOwner() { _; }\n  function f() external onlyOwner {}\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        assert!(has_access_control(target, src));
    }

    #[test]
    fn has_access_control_via_require() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    address owner;
    function f() public {
        require(msg.sender == owner, "no");
    }
}"#;
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(has_access_control(&funcs[0], src));
    }

    #[test]
    fn has_access_control_negative() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!has_access_control(&funcs[0], src));
    }

    // ===================================================================
    // func_body
    // ===================================================================

    #[test]
    fn func_body_returns_body() {
        let src =
            "pragma solidity ^0.8.0;\ncontract A {\n  function f() public { uint256 x = 1; }\n}";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let body = func_body(&funcs[0]);
        assert!(body.is_some());
        let text = node_text(&body.unwrap(), src);
        assert!(text.contains("uint256 x = 1"), "body: {}", text);
    }

    #[test]
    fn func_body_returns_none_for_non_function() {
        let src = "pragma solidity ^0.8.0;\ncontract A { uint256 x; }";
        let tree = parse(src);
        let contracts = find_nodes_of_kind(&tree.root_node(), "contract_declaration");
        assert!(func_body(&contracts[0]).is_none());
    }

    #[test]
    fn func_body_empty_body() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let body = func_body(&funcs[0]);
        assert!(body.is_some());
    }

    // ===================================================================
    // get_call_target / CallTarget
    // ===================================================================

    #[test]
    fn get_call_target_member_call() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f() public {
        msg.sender.call{value: 1}("");
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let member_calls: Vec<_> = calls
            .iter()
            .filter_map(|c| match get_call_target(c, src) {
                Some(CallTarget::MemberCall { .. }) => Some(get_call_target(c, src).unwrap()),
                _ => None,
            })
            .collect();
        assert!(
            !member_calls.is_empty(),
            "expected at least one member call"
        );
    }

    #[test]
    fn get_call_target_free_function() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f() public {
        require(true, "ok");
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let has_free = calls.iter().any(|c| {
            matches!(get_call_target(c, src), Some(CallTarget::FreeFunction { name }) if name == "require")
        });
        assert!(has_free, "expected require() to be parsed as FreeFunction");
    }

    #[test]
    fn get_call_target_returns_none_for_non_call() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(get_call_target(&funcs[0], src).is_none());
    }

    // ===================================================================
    // is_external_call
    // ===================================================================

    #[test]
    fn is_external_call_call_value() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f() public {
        msg.sender.call{value: 1}("");
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let has_ext = calls.iter().any(|c| is_external_call(c, src));
        assert!(has_ext, "msg.sender.call should be an external call");
    }

    #[test]
    fn is_external_call_transfer() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f(address payable to) public {
        to.transfer(1 ether);
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let has_ext = calls.iter().any(|c| is_external_call(c, src));
        assert!(has_ext, "to.transfer should be an external call");
    }

    #[test]
    fn is_external_call_require_is_not() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f() public {
        require(true, "ok");
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let any_ext = calls.iter().any(|c| is_external_call(c, src));
        assert!(!any_ext, "require() should not be an external call");
    }

    #[test]
    fn is_external_call_delegatecall() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f(address target) public {
        target.delegatecall(abi.encodeWithSignature("foo()"));
    }
}"#;
        let tree = parse(src);
        let calls = find_nodes_of_kind(&tree.root_node(), "call_expression");
        let has_ext = calls.iter().any(|c| is_external_call(c, src));
        assert!(has_ext, "target.delegatecall should be an external call");
    }

    // ===================================================================
    // is_state_write
    // ===================================================================

    #[test]
    fn is_state_write_assignment() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    uint256 public x;
    function f() public { x = 1; }
}"#;
        let tree = parse(src);
        let assignments = find_nodes_of_kind(&tree.root_node(), "assignment_expression");
        assert!(!assignments.is_empty(), "expected assignment_expression");
        assert!(assignments.iter().any(|a| is_state_write(a)));
    }

    #[test]
    fn is_state_write_augmented() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    uint256 public x;
    function f() public { x += 1; }
}"#;
        let tree = parse(src);
        let assignments = find_nodes_of_kind(&tree.root_node(), "augmented_assignment_expression");
        if !assignments.is_empty() {
            assert!(assignments.iter().any(|a| is_state_write(a)));
        }
    }

    #[test]
    fn is_state_write_false_for_non_assignment() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        assert!(!is_state_write(&funcs[0]));
    }

    // ===================================================================
    // has_solidity_gte_0_8
    // ===================================================================

    #[test]
    fn has_solidity_gte_0_8_caret() {
        let src = "pragma solidity ^0.8.0;\ncontract A {}";
        let tree = parse(src);
        assert!(has_solidity_gte_0_8(&tree.root_node(), src));
    }

    #[test]
    fn has_solidity_gte_0_8_specific_version() {
        let src = "pragma solidity 0.8.19;\ncontract A {}";
        let tree = parse(src);
        assert!(has_solidity_gte_0_8(&tree.root_node(), src));
    }

    #[test]
    fn has_solidity_gte_0_8_range() {
        let src = "pragma solidity >=0.8.0 <0.9.0;\ncontract A {}";
        let tree = parse(src);
        assert!(has_solidity_gte_0_8(&tree.root_node(), src));
    }

    #[test]
    fn has_solidity_gte_0_8_false_for_0_7() {
        let src = "pragma solidity ^0.7.0;\ncontract A {}";
        let tree = parse(src);
        assert!(!has_solidity_gte_0_8(&tree.root_node(), src));
    }

    #[test]
    fn has_solidity_gte_0_8_false_for_0_6() {
        let src = "pragma solidity ^0.6.12;\ncontract A {}";
        let tree = parse(src);
        assert!(!has_solidity_gte_0_8(&tree.root_node(), src));
    }

    #[test]
    fn has_solidity_gte_0_8_no_pragma() {
        let src = "contract A {}";
        let tree = parse(src);
        assert!(!has_solidity_gte_0_8(&tree.root_node(), src));
    }

    // ===================================================================
    // is_proxy_contract
    // ===================================================================

    #[test]
    fn is_proxy_contract_upgradeable() {
        let src = "pragma solidity ^0.8.0;\ncontract A is Upgradeable { }";
        let tree = parse(src);
        assert!(is_proxy_contract(&tree.root_node(), src));
    }

    #[test]
    fn is_proxy_contract_uups() {
        let src = "pragma solidity ^0.8.0;\nimport \"./UUPSUpgradeable.sol\";\ncontract A is UUPSUpgradeable { }";
        let tree = parse(src);
        assert!(is_proxy_contract(&tree.root_node(), src));
    }

    #[test]
    fn is_proxy_contract_with_delegatecall() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    function f(address impl) public {
        impl.delegatecall("");
    }
}"#;
        let tree = parse(src);
        assert!(is_proxy_contract(&tree.root_node(), src));
    }

    #[test]
    fn is_proxy_contract_false_for_plain() {
        let src = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }";
        let tree = parse(src);
        assert!(!is_proxy_contract(&tree.root_node(), src));
    }

    #[test]
    fn is_proxy_contract_transparent() {
        let src = "pragma solidity ^0.8.0;\ncontract A is TransparentProxy { }";
        let tree = parse(src);
        assert!(is_proxy_contract(&tree.root_node(), src));
    }

    // ===================================================================
    // Multiple modifiers on one function
    // ===================================================================

    #[test]
    fn function_with_multiple_modifiers() {
        let src = r#"pragma solidity ^0.8.0;
contract A {
    modifier onlyOwner() { _; }
    modifier nonReentrant() { _; }
    function f() external onlyOwner nonReentrant {}
}"#;
        let tree = parse(src);
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let target = funcs
            .iter()
            .find(|f| function_name(f, src) == Some("f"))
            .expect("expected function f");
        let mods = function_modifiers(target, src);
        assert!(mods.contains(&"onlyOwner"), "got: {:?}", mods);
        assert!(mods.contains(&"nonReentrant"), "got: {:?}", mods);
        assert!(has_reentrancy_guard(target, src));
        assert!(has_access_control_modifier(target, src));
    }

    // ===================================================================
    // Diagnostic helpers (run with --nocapture to see output)
    // ===================================================================

    fn dump_ast(node: &Node, source: &str, depth: usize) {
        let indent = "  ".repeat(depth);
        let text = &source[node.start_byte()..node.end_byte()];
        let preview: String = text.chars().take(80).collect();
        let preview = preview.replace('\n', "\\n");
        println!(
            "{}{} [{}:{}] «{}»",
            indent,
            node.kind(),
            node.start_position().row + 1,
            node.start_position().column,
            preview
        );
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            dump_ast(&child, source, depth + 1);
        }
    }

    #[test]
    fn ast_dump_call_patterns() {
        let source = r#"pragma solidity ^0.8.0;
contract Test {
    function a() public {
        msg.sender.call{value: 1}("");
    }
    function b(address payable to) public {
        to.transfer(100);
    }
    function c(address target) public {
        target.delegatecall(bytes(""));
    }
    function d() public {
        if (msg.sender != owner) revert("unauthorized");
    }
}"#;
        let tree = parse(source);
        dump_ast(&tree.root_node(), source, 0);
    }
}
