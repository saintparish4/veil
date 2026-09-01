use crate::ast_utils::{
    find_nodes_of_kind, func_body, get_call_target, is_external_call, is_state_write, node_text,
    CallTarget,
};
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
    /// Structured storage reads/writes extracted from `statements`, populated by the Builder.
    pub storage_ops: Vec<StorageOp>,
    pub successors: SmallVec<[BasicBlockId; 2]>,
    pub predecessors: SmallVec<[BasicBlockId; 4]>,
}

pub enum CfgStatement {
    ExternalCall {
        byte_offset: usize,
        line: usize,
        /// Optional rich metadata (call kind, target, value). `None` is always valid;
        /// detectors that don't need it pay no cost.
        meta: Option<Box<CallMeta>>,
    },
    StateWrite {
        byte_offset: usize,
        line: usize,
        /// Optional slot expression. `None` when the LHS couldn't be resolved.
        slot: Option<Box<StorageSlotExpr>>,
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
        /// Name of the called function when the callee could be resolved statically.
        callee_name: Option<String>,
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

/// How an external call is dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallKind {
    LowLevelCall,
    DelegateCall,
    StaticCall,
    Transfer,
    Send,
}

/// Rich metadata attached to an `ExternalCall` statement.
#[derive(Debug, Clone)]
pub struct CallMeta {
    pub call_kind: CallKind,
    /// The textual expression of the call target (e.g. `"addr"` in `addr.call(...)`).
    pub target_expr: Option<String>,
    /// Whether the call includes a `{value: ...}` option.
    pub value_sent: bool,
}

/// Describes the Solidity storage slot accessed by a `StateWrite` or `StateRead`.
#[derive(Debug, Clone)]
pub struct StorageSlotExpr {
    /// Full text of the LHS expression (e.g. `"balances[msg.sender]"`).
    pub slot_expr: String,
    /// True when the expression is a mapping access (contains `[`).
    pub is_mapping: bool,
    /// The key expression for a mapping access (e.g. `"msg.sender"`).
    pub key_expr: Option<String>,
}

/// A structured storage operation extracted from a basic block's statements.
#[derive(Debug, Clone)]
pub struct StorageOp {
    pub kind: StorageOpKind,
    pub slot: StorageSlotExpr,
    pub byte_offset: usize,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageOpKind {
    Load,
    Store,
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
            CfgStatement::ExternalCall { line, meta, .. } => {
                if let Some(m) = meta {
                    write!(f, "ExternalCall(line {}, {:?})", line, m.call_kind)
                } else {
                    write!(f, "ExternalCall(line {})", line)
                }
            }
            CfgStatement::StateWrite { line, slot, .. } => {
                if let Some(s) = slot {
                    write!(f, "StateWrite(line {}, slot={})", line, s.slot_expr)
                } else {
                    write!(f, "StateWrite(line {})", line)
                }
            }
            CfgStatement::LocalAssignment { byte_offset, .. } => {
                write!(f, "LocalAssignment(byte {})", byte_offset)
            }
            CfgStatement::Guard { byte_offset, kind } => {
                write!(f, "Guard({}, byte {})", kind, byte_offset)
            }
            CfgStatement::Emit { line, .. } => write!(f, "Emit(line {})", line),
            CfgStatement::Return { byte_offset } => write!(f, "Return(byte {})", byte_offset),
            CfgStatement::Revert { byte_offset } => write!(f, "Revert(byte {})", byte_offset),
            CfgStatement::InternalCall {
                line, callee_name, ..
            } => {
                if let Some(name) = callee_name {
                    write!(f, "InternalCall({}, line {})", name, line)
                } else {
                    write!(f, "InternalCall(line {})", line)
                }
            }
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
    /// bodies, ERROR nodes, inline assembly, or try/catch blocks.
    ///
    /// Called lazily from [`crate::detector_trait::AnalysisContext::cfg_for`].
    pub fn build_for_function(_tree: &Tree, source: &str, func: &Node) -> Option<ControlFlowGraph> {
        if func.has_error() || func.kind() != "function_definition" {
            return None;
        }

        let body = func_body(func)?;

        // Conservative: inline assembly has control flow we can't express in our IR.
        if !find_nodes_of_kind(&body, "assembly_statement").is_empty() {
            return None;
        }

        // Conservative: try/catch requires exception-edge modelling we don't have yet.
        if !find_nodes_of_kind(&body, "try_statement").is_empty() {
            return None;
        }

        let mut b = Builder::new(source);
        let entry = b.entry;
        let exit = b.exit;

        let stmts = stmt_children_of(body);
        let last = b.process_stmts(entry, exit, &stmts);

        if !b.is_terminated(last) && last != exit {
            b.connect(last, exit);
        }

        Some(ControlFlowGraph {
            entry,
            exit,
            blocks: b.blocks,
        })
    }
}

// ---------------------------------------------------------------------------
// CFG builder helpers (module-level)
// ---------------------------------------------------------------------------

fn is_statement_kind(kind: &str) -> bool {
    matches!(
        kind,
        // tree-sitter-solidity 1.x wraps every statement in a generic "statement" node
        "statement"
            | "block"
            | "statement_block"
            | "function_body"
            | "block_statement"
            | "expression_statement"
            | "if_statement"
            | "for_statement"
            | "while_statement"
            | "do_while_statement"
            | "return_statement"
            | "revert_statement"
            | "emit_statement"
            | "try_statement"
            | "assembly_statement"
            | "variable_declaration_statement"
            | "break_statement"
            | "continue_statement"
            | "throw_statement"
    )
}

fn named_children_of<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// Named children of a block/body node that are real statements (not comments/extras).
fn stmt_children_of<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| !n.is_extra())
        .collect()
}

/// Returns (then_body, else_body) for an `if_statement` node.
fn body_of_if<'a>(node: Node<'a>) -> (Option<Node<'a>>, Option<Node<'a>>) {
    // Try grammar-defined field names first (most reliable).
    let then = node
        .child_by_field_name("consequence")
        .or_else(|| node.child_by_field_name("body"));
    let else_ = node.child_by_field_name("alternative");
    if then.is_some() {
        return (then, else_);
    }
    // Fallback: collect named children that look like statements.
    let stmt_kids: Vec<Node<'a>> = named_children_of(node)
        .into_iter()
        .filter(|n| is_statement_kind(n.kind()))
        .collect();
    (stmt_kids.first().copied(), stmt_kids.get(1).copied())
}

/// Returns the body block/statement of a `for_statement` or `while_statement`.
fn body_of_for_while<'a>(node: Node<'a>) -> Option<Node<'a>> {
    node.child_by_field_name("body").or_else(|| {
        named_children_of(node)
            .into_iter()
            .rfind(|n| is_statement_kind(n.kind()))
    })
}

/// Returns the body block/statement of a `do_while_statement`.
fn body_of_do_while<'a>(node: Node<'a>) -> Option<Node<'a>> {
    node.child_by_field_name("body").or_else(|| {
        named_children_of(node)
            .into_iter()
            .find(|n| is_statement_kind(n.kind()))
    })
}

/// Unwrap the tree-sitter-solidity `statement` wrapper to reveal the actual statement kind.
fn unwrap_statement_node(node: Node) -> Node {
    if node.kind() == "statement" {
        if let Some(inner) = named_children_of(node).into_iter().find(|n| !n.is_extra()) {
            return inner;
        }
    }
    node
}

/// Returns `true` when an `if_statement` is purely a `if (cond) revert(...)` guard pattern
/// with no else branch.
fn is_if_revert_guard(if_node: &Node) -> bool {
    let (then_body, else_body) = body_of_if(*if_node);
    if else_body.is_some() {
        return false; // if/else is real branching, not a guard
    }
    match then_body {
        Some(b) => {
            let actual = unwrap_statement_node(b);
            if actual.kind() == "revert_statement" {
                return true;
            }
            // Block containing only a revert
            if is_statement_kind(actual.kind()) {
                let inner = stmt_children_of(actual);
                return inner.len() == 1 && {
                    let n = unwrap_statement_node(inner[0]);
                    n.kind() == "revert_statement"
                };
            }
            false
        }
        None => false,
    }
}

/// Returns `true` for calls that perform sensitive admin/protocol operations.
/// Covers: contract destruction, ownership transfers, protocol pause/upgrade hooks.
fn is_sensitive_call(node: &Node, source: &str) -> bool {
    let text = node_text(node, source);
    if text.contains("selfdestruct") || text.contains("suicide") {
        return true;
    }
    let target_name = match get_call_target(node, source) {
        Some(CallTarget::FreeFunction { name }) => name,
        Some(CallTarget::MemberCall { method, .. }) => method,
        None => return false,
    };
    matches!(
        target_name,
        "pause"
            | "unpause"
            | "initialize"
            | "init"
            | "setOwner"
            | "changeOwner"
            | "transferOwnership"
            | "setAdmin"
            | "addAdmin"
            | "upgrade"
            | "setImplementation"
            | "setFee"
            | "setRate"
    )
}

// ---------------------------------------------------------------------------
// Metadata helpers
// ---------------------------------------------------------------------------

/// Extract call kind and basic metadata from a `call_expression` node.
fn build_call_meta(call: &Node, source: &str) -> CallMeta {
    let call_text = node_text(call, source);
    let (call_kind, target_expr) = match get_call_target(call, source) {
        Some(CallTarget::MemberCall { method, object }) => {
            let kind = match method {
                "delegatecall" => CallKind::DelegateCall,
                "staticcall" => CallKind::StaticCall,
                "transfer" => CallKind::Transfer,
                "send" => CallKind::Send,
                _ => CallKind::LowLevelCall,
            };
            (kind, Some(object.to_string()))
        }
        Some(CallTarget::FreeFunction { name }) => (CallKind::LowLevelCall, Some(name.to_string())),
        None => (CallKind::LowLevelCall, None),
    };
    let value_sent = call_text.contains("{value:");
    CallMeta {
        call_kind,
        target_expr,
        value_sent,
    }
}

/// Extract storage slot expression from the LHS of an assignment.
fn build_slot_expr(assign: &Node, source: &str) -> Option<StorageSlotExpr> {
    let lhs = assign
        .child_by_field_name("left")
        .or_else(|| assign.child(0))?;
    let slot_expr = node_text(&lhs, source).to_string();
    let is_mapping = slot_expr.contains('[');
    let key_expr = if is_mapping {
        // Grab the first `[key]` subscript text as the key expression.
        lhs.children(&mut lhs.walk())
            .find(|c| c.kind() == "index_access" || c.kind() == "member_expression")
            .and_then(|ie| ie.child_by_field_name("index"))
            .map(|k| node_text(&k, source).to_string())
    } else {
        None
    };
    Some(StorageSlotExpr {
        slot_expr,
        is_mapping,
        key_expr,
    })
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

struct Builder<'s> {
    source: &'s str,
    blocks: Vec<BasicBlock>,
    next_id: usize,
    entry: BasicBlockId,
    exit: BasicBlockId,
}

impl<'s> Builder<'s> {
    fn new(source: &'s str) -> Self {
        let entry = BasicBlockId(0);
        let exit = BasicBlockId(1);
        let mut b = Self {
            source,
            blocks: Vec::with_capacity(8),
            next_id: 2,
            entry,
            exit,
        };
        b.blocks.push(BasicBlock {
            id: entry,
            statements: vec![],
            storage_ops: vec![],
            successors: SmallVec::new(),
            predecessors: SmallVec::new(),
        });
        b.blocks.push(BasicBlock {
            id: exit,
            statements: vec![],
            storage_ops: vec![],
            successors: SmallVec::new(),
            predecessors: SmallVec::new(),
        });
        b
    }

    fn alloc(&mut self) -> BasicBlockId {
        let id = BasicBlockId(self.next_id);
        self.next_id += 1;
        self.blocks.push(BasicBlock {
            id,
            statements: vec![],
            storage_ops: vec![],
            successors: SmallVec::new(),
            predecessors: SmallVec::new(),
        });
        id
    }

    fn idx(&self, id: BasicBlockId) -> Option<usize> {
        self.blocks.iter().position(|b| b.id == id)
    }

    fn connect(&mut self, from: BasicBlockId, to: BasicBlockId) {
        if let Some(i) = self.idx(from) {
            if !self.blocks[i].successors.contains(&to) {
                self.blocks[i].successors.push(to);
            }
        }
        if let Some(i) = self.idx(to) {
            if !self.blocks[i].predecessors.contains(&from) {
                self.blocks[i].predecessors.push(from);
            }
        }
    }

    fn push(&mut self, id: BasicBlockId, stmt: CfgStatement) {
        if let Some(i) = self.idx(id) {
            self.blocks[i].statements.push(stmt);
        }
    }

    /// A block is "terminated" when its last statement is Return or Revert.
    fn is_terminated(&self, id: BasicBlockId) -> bool {
        self.idx(id).is_some_and(|i| {
            self.blocks[i].statements.last().is_some_and(|s| {
                matches!(s, CfgStatement::Return { .. } | CfgStatement::Revert { .. })
            })
        })
    }

    /// Process a slice of statement nodes starting from `current`.
    /// Returns the last reachable block (may be terminated).
    fn process_stmts(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        stmts: &[Node],
    ) -> BasicBlockId {
        let mut block = current;
        for stmt in stmts {
            if self.is_terminated(block) {
                break; // dead code after terminator
            }
            block = self.process_stmt(block, exit, stmt);
        }
        block
    }

    fn process_stmt(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        node: &Node,
    ) -> BasicBlockId {
        match node.kind() {
            // tree-sitter-solidity 1.x wraps every statement inside a generic "statement" node;
            // unwrap by recursing into the first non-extra named child.
            "statement" => {
                let inner: Vec<_> = named_children_of(*node)
                    .into_iter()
                    .filter(|n| !n.is_extra())
                    .collect();
                if let Some(child) = inner.first() {
                    self.process_stmt(current, exit, child)
                } else {
                    current // empty statement wrapper
                }
            }

            "if_statement" => self.process_if(current, exit, node),

            "for_statement" | "while_statement" => self.process_for_while(current, exit, node),

            "do_while_statement" => self.process_do_while(current, exit, node),

            "return_statement" => {
                self.push(
                    current,
                    CfgStatement::Return {
                        byte_offset: node.start_byte(),
                    },
                );
                self.connect(current, exit);
                current
            }

            "revert_statement" | "throw_statement" => {
                self.push(
                    current,
                    CfgStatement::Revert {
                        byte_offset: node.start_byte(),
                    },
                );
                self.connect(current, exit);
                current
            }

            "emit_statement" => {
                let line = node.start_position().row + 1;
                self.push(
                    current,
                    CfgStatement::Emit {
                        byte_offset: node.start_byte(),
                        line,
                    },
                );
                current
            }

            "expression_statement" => {
                let stmt = self.classify_expr_stmt(node);
                let is_revert = matches!(stmt, CfgStatement::Revert { .. });
                self.push(current, stmt);
                if is_revert {
                    self.connect(current, exit);
                }
                current
            }

            "variable_declaration_statement" => {
                let stmt = self.classify_var_decl(node);
                self.push(current, stmt);
                current
            }

            // Nested blocks (anonymous scopes are rare but valid Solidity).
            "block" | "statement_block" | "block_statement" | "function_body" => {
                let stmts = stmt_children_of(*node);
                self.process_stmts(current, exit, &stmts)
            }

            // break/continue: conservatively treated as Other (loop exits modelled via
            // back-edges from the loop-body end; break would ideally go to `after` but
            // the over-approximation is sound for taint).
            "break_statement" | "continue_statement" => {
                self.push(
                    current,
                    CfgStatement::Other {
                        byte_offset: node.start_byte(),
                    },
                );
                current
            }

            _ => {
                self.push(
                    current,
                    CfgStatement::Other {
                        byte_offset: node.start_byte(),
                    },
                );
                current
            }
        }
    }

    fn process_if(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        node: &Node,
    ) -> BasicBlockId {
        // `if (cond) revert(...)` with no else → model as Guard (semantically require(cond)).
        if is_if_revert_guard(node) {
            self.push(
                current,
                CfgStatement::Guard {
                    byte_offset: node.start_byte(),
                    kind: GuardKind::IfRevert,
                },
            );
            return current;
        }

        let merge = self.alloc();
        let (then_node, else_node) = body_of_if(*node);

        if let Some(else_n) = else_node {
            let then_block = self.alloc();
            let else_block = self.alloc();
            self.connect(current, then_block);
            self.connect(current, else_block);

            if let Some(tn) = then_node {
                let end = self.process_body(then_block, exit, &tn);
                if !self.is_terminated(end) {
                    self.connect(end, merge);
                }
            } else {
                self.connect(then_block, merge);
            }

            let end = self.process_body(else_block, exit, &else_n);
            if !self.is_terminated(end) {
                self.connect(end, merge);
            }
        } else {
            let then_block = self.alloc();
            self.connect(current, then_block);
            self.connect(current, merge);

            if let Some(tn) = then_node {
                let end = self.process_body(then_block, exit, &tn);
                if !self.is_terminated(end) {
                    self.connect(end, merge);
                }
            } else {
                self.connect(then_block, merge);
            }
        }

        merge
    }

    fn process_for_while(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        node: &Node,
    ) -> BasicBlockId {
        // current → header → [body_block, after]; body_block → header (back-edge).
        let header = self.alloc();
        let body_block = self.alloc();
        let after = self.alloc();

        self.connect(current, header);
        self.connect(header, body_block);
        self.connect(header, after);

        if let Some(body) = body_of_for_while(*node) {
            let end = self.process_body(body_block, exit, &body);
            if !self.is_terminated(end) {
                self.connect(end, header); // back-edge
            }
        } else {
            self.connect(body_block, header);
        }

        after
    }

    fn process_do_while(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        node: &Node,
    ) -> BasicBlockId {
        let body_block = self.alloc();
        let after = self.alloc();

        self.connect(current, body_block);

        if let Some(body) = body_of_do_while(*node) {
            let end = self.process_body(body_block, exit, &body);
            if !self.is_terminated(end) {
                self.connect(end, body_block); // back-edge (iterate again)
                self.connect(end, after); // or exit loop
            }
        } else {
            self.connect(body_block, after);
        }

        after
    }

    /// Process either a block node (recurse into children) or a single statement.
    fn process_body(
        &mut self,
        current: BasicBlockId,
        exit: BasicBlockId,
        node: &Node,
    ) -> BasicBlockId {
        match node.kind() {
            "block" | "statement_block" | "function_body" | "block_statement" => {
                let stmts = stmt_children_of(*node);
                self.process_stmts(current, exit, &stmts)
            }
            _ => self.process_stmt(current, exit, node),
        }
    }

    /// Classify an `expression_statement` into the appropriate `CfgStatement`.
    fn classify_expr_stmt(&self, node: &Node) -> CfgStatement {
        let byte_offset = node.start_byte();
        let line = node.start_position().row + 1;

        // Search descendants for call_expression nodes.
        let calls = find_nodes_of_kind(node, "call_expression");

        // Priority 1: external calls (.call / .send / .transfer / .delegatecall / .staticcall).
        for call in &calls {
            if is_external_call(call, self.source) {
                let meta = build_call_meta(call, self.source);
                return CfgStatement::ExternalCall {
                    byte_offset: call.start_byte(),
                    line: call.start_position().row + 1,
                    meta: Some(Box::new(meta)),
                };
            }
        }

        // Priority 2: guard calls (require / assert).
        for call in &calls {
            if let Some(CallTarget::FreeFunction { name }) = get_call_target(call, self.source) {
                match name {
                    "require" => {
                        return CfgStatement::Guard {
                            byte_offset: call.start_byte(),
                            kind: GuardKind::Require,
                        };
                    }
                    "assert" => {
                        return CfgStatement::Guard {
                            byte_offset: call.start_byte(),
                            kind: GuardKind::Assert,
                        };
                    }
                    "revert" => {
                        // revert() function-call form (pre-0.8 style).
                        return CfgStatement::Revert {
                            byte_offset: call.start_byte(),
                        };
                    }
                    _ => {}
                }
            }
        }

        // Priority 3: sensitive calls (selfdestruct / suicide).
        for call in &calls {
            if is_sensitive_call(call, self.source) {
                return CfgStatement::InternalCallSensitive {
                    byte_offset: call.start_byte(),
                    line: call.start_position().row + 1,
                };
            }
        }

        // Priority 4: other function calls → InternalCall.
        if !calls.is_empty() {
            let callee_name = calls.first().and_then(|c| {
                if let Some(CallTarget::FreeFunction { name }) = get_call_target(c, self.source) {
                    Some(name.to_string())
                } else {
                    None
                }
            });
            return CfgStatement::InternalCall {
                byte_offset,
                line,
                callee_name,
            };
        }

        // Priority 5: assignment expressions.
        let assignments = find_nodes_of_kind(node, "assignment_expression");
        let augmented = find_nodes_of_kind(node, "augmented_assignment_expression");

        if let Some(assign) = assignments.iter().chain(augmented.iter()).next() {
            return if is_state_write(assign) {
                let slot = build_slot_expr(assign, self.source);
                CfgStatement::StateWrite {
                    byte_offset: assign.start_byte(),
                    line: assign.start_position().row + 1,
                    slot: slot.map(Box::new),
                }
            } else {
                CfgStatement::LocalAssignment {
                    byte_offset: assign.start_byte(),
                    line: assign.start_position().row + 1,
                }
            };
        }

        CfgStatement::Other { byte_offset }
    }

    /// Classify a `variable_declaration_statement`.
    ///
    /// `(bool ok, ) = addr.call{...}("")` is a variable declaration whose initialiser
    /// contains an external call; we classify the whole statement as ExternalCall so
    /// that taint can flow from it.
    fn classify_var_decl(&self, node: &Node) -> CfgStatement {
        let byte_offset = node.start_byte();
        let line = node.start_position().row + 1;

        let calls = find_nodes_of_kind(node, "call_expression");
        for call in &calls {
            if is_external_call(call, self.source) {
                let meta = build_call_meta(call, self.source);
                return CfgStatement::ExternalCall {
                    byte_offset: call.start_byte(),
                    line: call.start_position().row + 1,
                    meta: Some(Box::new(meta)),
                };
            }
        }

        CfgStatement::LocalAssignment { byte_offset, line }
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

    /// Hand-built CFG covering every block kind, used to pin the `Display` snapshot.
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
                storage_ops: vec![],
                successors: smallvec![BasicBlockId(1), BasicBlockId(2)],
                predecessors: smallvec![],
            },
            BasicBlock {
                id: BasicBlockId(1),
                statements: vec![CfgStatement::ExternalCall {
                    byte_offset: 100,
                    line: 8,
                    meta: None,
                }],
                storage_ops: vec![],
                successors: smallvec![BasicBlockId(3)],
                predecessors: smallvec![BasicBlockId(0)],
            },
            BasicBlock {
                id: BasicBlockId(2),
                statements: vec![CfgStatement::StateWrite {
                    byte_offset: 120,
                    line: 10,
                    slot: None,
                }],
                storage_ops: vec![],
                successors: smallvec![BasicBlockId(3)],
                predecessors: smallvec![BasicBlockId(0)],
            },
            BasicBlock {
                id: BasicBlockId(3),
                statements: vec![],
                storage_ops: vec![],
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
            // Empty body → entry connected directly to exit, no statements.
            let cfg = cfg.expect("empty body should produce a minimal entry→exit CFG");
            assert!(cfg.block(cfg.entry).is_some());
            assert!(cfg.block(cfg.exit).is_some());
            assert!(cfg
                .block(cfg.entry)
                .expect("entry block exists")
                .statements
                .is_empty());
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
            let cfg = cfg.expect("single-statement function should produce a CFG");
            // Entry block should contain the Guard statement.
            let entry_block = cfg.block(cfg.entry).expect("entry block exists");
            assert!(
                entry_block
                    .statements
                    .iter()
                    .any(|s| matches!(s, CfgStatement::Guard { .. })),
                "expected a Guard statement in entry block, got: {:?}",
                entry_block
                    .statements
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
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
            let cfg = cfg.expect("deeply nested branches should produce a CFG");
            // Should have multiple blocks (entry + many if-branches + merge blocks).
            assert!(
                cfg.blocks.len() > 3,
                "expected multiple blocks for nested ifs"
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
            assert!(
                cfg.is_none(),
                "try/catch: conservative None (not yet handled)"
            );
        }

        #[test]
        fn modifier_only_function_body_just_underscore() {
            let src = r#"pragma solidity ^0.8.0;
            contract C {
                modifier m() { _; }
                function f() external m() { }
            }"#;
            let cfg = build_cfg_for_first_function(src);
            // Empty body with modifier: modifier inlining is deferred; raw body is empty.
            let cfg = cfg.expect("empty body with modifier should produce a minimal CFG");
            assert!(cfg.block(cfg.entry).is_some());
        }
    }
}
