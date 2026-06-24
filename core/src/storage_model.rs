//! Contract storage layout model.
//!
//! Builds a `StorageModel` by scanning `state_variable_declaration` nodes in the
//! contract body, assigning sequential slot indices in declaration order (conservatively
//! assuming no packing — accurate for most detector use cases).
//!
//! Constants and immutables are skipped because they don't occupy storage slots.
//!
//! # Usage
//! ```ignore
//! let model = ctx.storage_model();
//! for slot in &model.slots {
//!     println!("slot {}: {} ({})", slot.index, slot.name, slot.type_name);
//! }
//! ```

use crate::ast_utils::{find_nodes_of_kind, node_text};
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Layout of all storage variables in a contract, in declaration order.
#[derive(Debug, Clone)]
pub struct StorageModel {
    /// All storage slots, indexed 0, 1, 2, … in declaration order.
    /// Constants and immutables are excluded.
    pub slots: Vec<StorageSlot>,
}

/// A single declared storage variable and its slot position.
#[derive(Debug, Clone)]
pub struct StorageSlot {
    /// Slot index in declaration order (0-based). Does not account for struct packing.
    pub index: usize,
    /// Variable name (e.g. `"balances"`, `"owner"`).
    pub name: String,
    /// Solidity type text (e.g. `"uint256"`, `"mapping(address => uint256)"`).
    pub type_name: String,
    /// Byte offset of the declaration in the source.
    pub byte_offset: usize,
    /// 1-based line number of the declaration.
    pub line: usize,
}

impl StorageModel {
    /// Find a slot by variable name (case-sensitive).
    pub fn slot_by_name(&self, name: &str) -> Option<&StorageSlot> {
        self.slots.iter().find(|s| s.name == name)
    }

    /// Find a slot by its index.
    pub fn slot_by_index(&self, index: usize) -> Option<&StorageSlot> {
        self.slots.iter().find(|s| s.index == index)
    }

    /// Returns `true` if any slot holds a value of a type that might store an address
    /// (addresses, mappings to addresses, or contract interface types).
    pub fn has_address_slot(&self) -> bool {
        self.slots
            .iter()
            .any(|s| s.type_name.contains("address") || s.type_name.starts_with("I"))
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a storage layout model from the contract's AST.
///
/// Walks all `state_variable_declaration` nodes reachable from `root`.
/// Assignments, local variables, and function parameters are not included.
pub fn build_storage_model(root: &Node, source: &str) -> StorageModel {
    let decls = find_nodes_of_kind(root, "state_variable_declaration");

    let mut slots = Vec::new();
    let mut index = 0;

    for decl in decls {
        // Skip constants and immutables — they don't occupy runtime storage.
        let decl_text = node_text(&decl, source);
        if decl_text.contains("constant") || decl_text.contains("immutable") {
            continue;
        }

        let name = extract_field_text(&decl, "name", source);
        let type_name = extract_field_text(&decl, "type", source);

        slots.push(StorageSlot {
            index,
            name,
            type_name,
            byte_offset: decl.start_byte(),
            line: decl.start_position().row + 1,
        });
        index += 1;
    }

    StorageModel { slots }
}

/// Extract the text of a named field child of `node`, or empty string if absent.
fn extract_field_text(node: &Node, field: &str, source: &str) -> String {
    node.child_by_field_name(field)
        .map(|n| node_text(&n, source).to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::new_solidity_parser;

    fn model_for(src: &str) -> StorageModel {
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(src, None).expect("parse");
        build_storage_model(&tree.root_node(), src)
    }

    #[test]
    fn basic_slot_assignment() {
        let src = r#"pragma solidity ^0.8.0;
contract Token {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
}"#;
        let model = model_for(src);
        assert_eq!(model.slots.len(), 3);
        assert_eq!(model.slots[0].name, "owner");
        assert_eq!(model.slots[0].index, 0);
        assert_eq!(model.slots[1].name, "totalSupply");
        assert_eq!(model.slots[1].index, 1);
        assert_eq!(model.slots[2].name, "balances");
        assert_eq!(model.slots[2].index, 2);
    }

    #[test]
    fn constants_excluded() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    uint256 public constant MAX = 1000;
    address public owner;
}"#;
        let model = model_for(src);
        assert_eq!(model.slots.len(), 1, "constant should be excluded");
        assert_eq!(model.slots[0].name, "owner");
        assert_eq!(model.slots[0].index, 0);
    }

    #[test]
    fn immutables_excluded() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    address public immutable factory;
    uint256 public cap;
}"#;
        let model = model_for(src);
        assert_eq!(model.slots.len(), 1);
        assert_eq!(model.slots[0].name, "cap");
    }

    #[test]
    fn slot_by_name_lookup() {
        let src = r#"pragma solidity ^0.8.0;
contract C { address public owner; uint256 public value; }"#;
        let model = model_for(src);
        assert!(model.slot_by_name("owner").is_some());
        assert!(model.slot_by_name("value").is_some());
        assert!(model.slot_by_name("nonexistent").is_none());
    }

    #[test]
    fn has_address_slot_detects_addresses() {
        let src = r#"pragma solidity ^0.8.0;
contract C { address public impl; uint256 public v; }"#;
        let model = model_for(src);
        assert!(model.has_address_slot());
    }

    #[test]
    fn no_state_variables() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function f() external pure returns (uint256) { return 42; }
}"#;
        let model = model_for(src);
        assert!(model.slots.is_empty());
    }
}
