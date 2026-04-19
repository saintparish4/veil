use smallvec::SmallVec;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BasicBlockId(pub usize);

pub struct ControlFlowGraph {
    pub entry: BasicBlockId,
    pub exit: BasicBlockId,
    pub blocks: Vec<BasicBlock>,
}

pub struct BasicBlock {
    pub id: BasicBlockId,
    pub statements: Vec<CfgStatement>,
    pub successors: SmallVec<[BasicBlockId; 2]>,
    pub predecessors: SmallVec<[BasicBlockId; 4]>,
}

pub enum CfgStatement {
    ExternalCall {
        byte_offset: usize,
        line: usize,
    },
    StateWrite {
        byte_offset: usize,
        line: usize,
    },
    LocalAssignment {
        byte_offset: usize,
        line: usize,
    },
    Guard {
        byte_offset: usize,
        kind: GuardKind,
    },
    Emit {
        byte_offset: usize,
        line: usize,
    },
    Return {
        byte_offset: usize,
    },
    Revert {
        byte_offset: usize,
    },
    InternalCall {
        byte_offset: usize,
        line: usize,
    },
    /// Internal call to a sensitive target (e.g. delegatecall, selfdestruct, pause).
    InternalCallSensitive {
        byte_offset: usize,
        line: usize,
    },
    Other {
        byte_offset: usize,
    },
}

pub enum GuardKind {
    Require,
    Assert,
    IfRevert,
}

impl fmt::Display for GuardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardKind::Require => write!(f, "require"),
            GuardKind::Assert => write!(f, "assert"),
            GuardKind::IfRevert => write!(f, "if_revert"),
        }
    }
}

impl fmt::Display for CfgStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CfgStatement::ExternalCall { line, .. } => write!(f, "ExternalCall(line {})", line),
            CfgStatement::StateWrite { line, .. } => write!(f, "StateWrite(line {})", line),
            CfgStatement::LocalAssignment { byte_offset, .. } => {
                write!(f, "LocalAssignment(byte {})", byte_offset)
            }
            CfgStatement::Guard { byte_offset, kind } => {
                write!(f, "Guard({}, byte {})", kind, byte_offset)
            }
            CfgStatement::Emit { line, .. } => write!(f, "Emit(line {})", line),
            CfgStatement::Return { byte_offset } => write!(f, "Return(byte {})", byte_offset),
            CfgStatement::Revert { byte_offset } => write!(f, "Revert(byte {})", byte_offset),
            CfgStatement::InternalCall { line, .. } => write!(f, "InternalCall(line {})", line),
            CfgStatement::InternalCallSensitive { line, .. } => {
                write!(f, "InternalCallSensitive(line {})", line)
            }
            CfgStatement::Other { byte_offset } => write!(f, "Other(byte {})", byte_offset),
        }
    }
}

impl ControlFlowGraph {
    /// Pretty-print the CFG for snapshot tests and debugging. Block order is by id.
    pub fn display_with_labels(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut blocks: Vec<_> = self.blocks.iter().collect();
        blocks.sort_by_key(|b| b.id.0);
        for block in blocks {
            let id = block.id.0;
            let entry_tag = if block.id == self.entry {
                " [entry]"
            } else {
                ""
            };
            let exit_tag = if block.id == self.exit { " [exit]" } else { "" };
            writeln!(f, "BB{}{}{}:", id, entry_tag, exit_tag)?;
            for stmt in &block.statements {
                writeln!(f, "  {}", stmt)?;
            }
            if !block.successors.is_empty() {
                let succs: Vec<String> = block
                    .successors
                    .iter()
                    .map(|s| format!("BB{}", s.0))
                    .collect();
                writeln!(f, "  -> {}", succs.join(", "))?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ControlFlowGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display_with_labels(f)
    }
}

/// # CFG Builder Logic
///
/// - **Build per function:** Construct a Control Flow Graph (CFG) for each function from the tree-sitter AST.
/// - **If statements:** Each `if_statement` introduces a branch: create a block for the condition, and add two successors (one for the true branch, one for the false or fallthrough).
/// - **Loops (for/while):** Each `for_statement` and `while_statement` should have a back-edge from the loop body block(s) to the loop condition block, representing potential repeated execution.
/// - **Return/Revert:** Each `return_statement` or `revert_statement` leads directly to the exit block, terminating the current basic block.
/// - **Sequential statements:** All sequential, non-branching statements are appended to the current basic block.
/// - **Statement Classification:** Classify each statement as one of the `CfgStatement` variants, using helpers from `ast_utils.rs` (e.g., `is_external_call`, `is_state_write`, etc).
/// - **Modifier inlining:** When processing a function with modifiers, locate the modifier's body, split at the `_` placeholder, and wrap as:
///   `[modifier_pre_statements] ++ [function_body_statements] ++ [modifier_post_statements]`.
/// - **Return value:** Returns `Option<ControlFlowGraph>`. Returns `None` for ASTs with no body (abstract/interface signatures), ERROR nodes, or if inline assembly with control flow is detected.
/// - **Display implementation:** Implement `Display` for `ControlFlowGraph` to facilitate readable snapshot test output.
///
/// # Design Notes
///
/// - Use `byte_offset` for position fields instead of node IDs (tree-sitter node IDs are memory addresses and not stable).
/// - Use `SmallVec<[BasicBlockId; 2]>` for block successors (if/loop branching is ≤2), to avoid unnecessary heap allocations.
/// - Use `SmallVec<[BasicBlockId; 4]>` for predecessors: blocks where control flow merges typically have 2–4 incoming edges.
/// - Clearly separate `StateWrite` vs `LocalAssignment` in `CfgStatement`: state modification vs stack/variable updates.
/// - Unify all guard checks via `Guard { kind }`—covers `require(...)`, `assert(...)`, and `if (...) revert(...)`.
/// - Use explicit variants for `Emit`, `Return`, `Revert`, and `InternalCall` so detectors do not need to inspect `Other`.
/// - The `Other` variant serves as a generic/catch-all for statements irrelevant to taint or control flow analysis.
///
/// # Additional Notes
///
/// - CFG builder is intended for **intra-function** analysis (no cross-function or contract-level graphs).
/// - All block indices (`BasicBlockId`) should remain stable across repeated builds for the same AST structure—do not rely on AST pointer IDs.
/// - For Solidity inline assembly (`YulBlock`) which may contain control flow, the builder conservatively returns `None`.
/// - Modifier inlining is essential for accurate dataflow: Solidity executes all modifier code except at the `_` placeholder, which is replaced with the function body.
///   - _Example:_ For a modifier with code before and after the `_`, the function body executes between these segments in the CFG.
/// - Snapshot testing and CI may dump the CFG in a human-readable form, so ensure `Display` implementation is concise, deterministic, and stable.
///
/// # Example Usage
/// ```ignore
/// if let Some(cfg) = ControlFlowGraph::build_for_function(tree, source, &func_node) {
///     println!("{}", cfg); // Pretty-printed for debugging or snapshot
/// }
/// ```
impl ControlFlowGraph {
    /// Returns the basic block for the given id, if present.
    pub fn block(&self, id: BasicBlockId) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Back edges (tail, head) in the CFG: edges from a block to an ancestor in the DFS tree.
    /// Used to detect loops; the head of a back edge is the loop header.
    pub fn back_edges(&self) -> Vec<(BasicBlockId, BasicBlockId)> {
        let mut stack = Vec::new();
        let mut visited = HashSet::new();
        let mut back = Vec::new();
        self.dfs_back_edges(self.entry, &mut stack, &mut visited, &mut back);
        back
    }

    fn dfs_back_edges(
        &self,
        id: BasicBlockId,
        stack: &mut Vec<BasicBlockId>,
        visited: &mut HashSet<BasicBlockId>,
        back: &mut Vec<(BasicBlockId, BasicBlockId)>,
    ) {
        if stack.contains(&id) {
            return;
        }
        if !visited.insert(id) {
            return;
        }
        stack.push(id);
        let block = match self.block(id) {
            Some(b) => b,
            None => {
                stack.pop();
                return;
            }
        };
        for &succ in &block.successors {
            if stack.contains(&succ) {
                back.push((id, succ));
            } else {
                self.dfs_back_edges(succ, stack, visited, back);
            }
        }
        stack.pop();
    }

    /// Natural loop for back edge (tail, head): head plus all blocks that can reach tail
    /// without going through head. Used to inspect the loop body (e.g. for external calls).
    pub fn loop_blocks_for_back_edge(
        &self,
        tail: BasicBlockId,
        head: BasicBlockId,
    ) -> Vec<BasicBlockId> {
        let mut body = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(tail);
        while let Some(id) = queue.pop_front() {
            if id == head {
                continue;
            }
            if !body.insert(id) {
                continue;
            }
            let block = match self.block(id) {
                Some(b) => b,
                None => continue,
            };
            for &pred in &block.predecessors {
                queue.push_back(pred);
            }
        }
        body.insert(head);
        body.into_iter().collect()
    }

    /// Returns true if any block in the given set contains an `ExternalCall` statement.
    pub fn blocks_contain_external_call(&self, block_ids: &[BasicBlockId]) -> bool {
        block_ids.iter().any(|&id| {
            self.block(id).is_some_and(|b| {
                b.statements
                    .iter()
                    .any(|s| matches!(s, CfgStatement::ExternalCall { .. }))
            })
        })
    }

    /// Build a CFG for a single function node. Returns `None` for abstract/interface
    /// bodies, ERROR nodes, or when the full builder is not yet implemented.
    ///
    /// Called lazily from [`crate::detector_trait::AnalysisContext::cfg_for`].
    pub fn build_for_function(
        _tree: &Tree,
        _source: &str,
        _func: &Node,
    ) -> Option<ControlFlowGraph> {
        // TODO: full AST-based CFG construction (branches, loops, modifier inlining).
        None
    }
}

// ---------------------------------------------------------------------------
// Tests: Display snapshot + CFG construction edge cases
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_utils::find_nodes_of_kind;
    use crate::scan::new_solidity_parser;
    use smallvec::smallvec;

    /// Hand-built CFG matching the phase-s3 example format for Display snapshot.
    fn example_cfg() -> ControlFlowGraph {
        let entry = BasicBlockId(0);
        let exit = BasicBlockId(3);
        let blocks = vec![
            BasicBlock {
                id: BasicBlockId(0),
                statements: vec![CfgStatement::Guard {
                    byte_offset: 45,
                    kind: GuardKind::Require,
                }],
                successors: smallvec![BasicBlockId(1), BasicBlockId(2)],
                predecessors: smallvec![],
            },
            BasicBlock {
                id: BasicBlockId(1),
                statements: vec![CfgStatement::ExternalCall {
                    byte_offset: 100,
                    line: 8,
                }],
                successors: smallvec![BasicBlockId(3)],
                predecessors: smallvec![BasicBlockId(0)],
            },
            BasicBlock {
                id: BasicBlockId(2),
                statements: vec![CfgStatement::StateWrite {
                    byte_offset: 120,
                    line: 10,
                }],
                successors: smallvec![BasicBlockId(3)],
                predecessors: smallvec![BasicBlockId(0)],
            },
            BasicBlock {
                id: BasicBlockId(3),
                statements: vec![],
                successors: smallvec![],
                predecessors: smallvec![BasicBlockId(1), BasicBlockId(2)],
            },
        ];
        ControlFlowGraph {
            entry,
            exit,
            blocks,
        }
    }

    #[test]
    fn cfg_display_snapshot() {
        let cfg = example_cfg();
        let got = format!("{}", cfg);
        insta::assert_snapshot!(got, @r##"
        BB0 [entry]:
          Guard(require, byte 45)
          -> BB1, BB2
        BB1:
          ExternalCall(line 8)
          -> BB3
        BB2:
          StateWrite(line 10)
          -> BB3
        BB3 [exit]:

        "##);
    }

    /// Parse source, get first function_definition node, call build_for_function.
    fn build_cfg_for_first_function(source: &str) -> Option<ControlFlowGraph> {
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(source, None).expect("parse");
        let funcs = find_nodes_of_kind(&tree.root_node(), "function_definition");
        let func = funcs.first()?;
        ControlFlowGraph::build_for_function(&tree, source, func)
    }

    mod cfg_construction_edge_cases {
        use super::*;

        #[test]
        fn empty_function_body() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                function f() external { }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(
                cfg.is_none(),
                "empty body: builder may return None until implemented"
            );
        }

        #[test]
        fn abstract_function_no_body() {
            let src = r#"pragma solidity ^0.8.0;
            abstract contract C {
                function f() external;
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(cfg.is_none(), "abstract function has no body");
        }

        #[test]
        fn single_statement_function() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                function f() external {
                    require(true);
                }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(
                cfg.is_none(),
                "single-statement: builder returns None until implemented"
            );
        }

        #[test]
        fn inline_assembly_block() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                function f() external {
                    assembly {
                        let x := 1
                    }
                }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(cfg.is_none(), "inline assembly: conservative None");
        }

        #[test]
        fn error_node_partial_parse() {
            let src = "contract C { function f() external { ";
            let cfg = build_cfg_for_first_function(src);
            assert!(
                cfg.is_none(),
                "ERROR node / partial parse should yield None"
            );
        }

        #[test]
        fn deeply_nested_branches() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                function f() external {
                    if (true) { if (true) { if (true) { if (true) { if (true) {
                    if (true) { if (true) { if (true) { if (true) { if (true) {
                        require(true);
                    } } } } } } } } } }
                }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(
                cfg.is_none(),
                "deeply nested: None until builder implemented"
            );
        }

        #[test]
        fn try_catch_blocks() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                function f() external {
                    try this.f() {} catch {}
                }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(cfg.is_none(), "try/catch: None until builder handles it");
        }

        #[test]
        fn modifier_only_function_body_just_underscore() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                modifier m() { _; }
                function f() external m() { }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            assert!(
                cfg.is_none(),
                "modifier-only / body just _: None until implemented"
            );
        }
    }
}
