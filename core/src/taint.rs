//! Generic taint analysis over control flow graphs.
//!
//! Forward dataflow worklist: O(V+E) for acyclic CFGs, bounded by MAX_ITERATIONS
//! for loops. Used by reentrancy, unchecked_calls, access_control, etc.

use crate::cfg::{BasicBlockId, CfgStatement, ControlFlowGraph};
use std::collections::{HashMap, VecDeque};

/// Statement kind for taint query (matches [`CfgStatement`] variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CfgStatementKind {
    ExternalCall,
    StateWrite,
    LocalAssignment,
    Guard,
    Emit,
    Return,
    Revert,
    InternalCall,
    /// Internal call to a sensitive target (e.g. delegatecall, selfdestruct); used for access-control.
    InternalCallSensitive,
    /// Reaching the function exit block (fall-through) while tainted; used e.g. for unchecked-calls.
    ExitBlock,
    /// Entry block: path starts at function entry (taint source for access-control).
    EntryBlock,
    Other,
}

fn kind_of(stmt: &CfgStatement) -> CfgStatementKind {
    match stmt {
        CfgStatement::ExternalCall { .. } => CfgStatementKind::ExternalCall,
        CfgStatement::StateWrite { .. } => CfgStatementKind::StateWrite,
        CfgStatement::LocalAssignment { .. } => CfgStatementKind::LocalAssignment,
        CfgStatement::Guard { .. } => CfgStatementKind::Guard,
        CfgStatement::Emit { .. } => CfgStatementKind::Emit,
        CfgStatement::Return { .. } => CfgStatementKind::Return,
        CfgStatement::Revert { .. } => CfgStatementKind::Revert,
        CfgStatement::InternalCall { .. } => CfgStatementKind::InternalCall,
        CfgStatement::InternalCallSensitive { .. } => CfgStatementKind::InternalCallSensitive,
        CfgStatement::Other { .. } => CfgStatementKind::Other,
    }
}

fn line_of(stmt: &CfgStatement) -> usize {
    match stmt {
        CfgStatement::ExternalCall { line, .. } => *line,
        CfgStatement::StateWrite { line, .. } => *line,
        CfgStatement::LocalAssignment { .. } => 0,
        CfgStatement::Guard { byte_offset: _, .. } => 0,
        CfgStatement::Emit { line, .. } => *line,
        CfgStatement::Return { .. } => 0,
        CfgStatement::Revert { .. } => 0,
        CfgStatement::InternalCall { line, .. } => *line,
        CfgStatement::InternalCallSensitive { line, .. } => *line,
        CfgStatement::Other { .. } => 0,
    }
}

fn byte_offset_of(stmt: &CfgStatement) -> usize {
    match stmt {
        CfgStatement::ExternalCall { byte_offset, .. } => *byte_offset,
        CfgStatement::StateWrite { byte_offset, .. } => *byte_offset,
        CfgStatement::LocalAssignment { byte_offset, .. } => *byte_offset,
        CfgStatement::Guard { byte_offset, .. } => *byte_offset,
        CfgStatement::Emit { byte_offset, .. } => *byte_offset,
        CfgStatement::Return { byte_offset, .. } => *byte_offset,
        CfgStatement::Revert { byte_offset, .. } => *byte_offset,
        CfgStatement::InternalCall { byte_offset, .. } => *byte_offset,
        CfgStatement::InternalCallSensitive { byte_offset, .. } => *byte_offset,
        CfgStatement::Other { byte_offset, .. } => *byte_offset,
    }
}

/// Taint state along a path: tainted flag plus source location for reporting.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
struct TaintState {
    tainted: bool,
    source_byte: usize,
    source_line: usize,
}

fn merge_state(a: TaintState, b: TaintState) -> TaintState {
    TaintState {
        tainted: a.tainted || b.tainted,
        source_byte: if a.tainted {
            a.source_byte
        } else {
            b.source_byte
        },
        source_line: if a.tainted {
            a.source_line
        } else {
            b.source_line
        },
    }
}

pub struct TaintQuery {
    pub sources: Vec<CfgStatementKind>,
    pub sinks: Vec<CfgStatementKind>,
    pub sanitizers: Vec<CfgStatementKind>,
}

#[derive(Debug)]
pub struct TaintViolation {
    pub source_line: usize,
    pub sink_line: usize,
    pub source_byte_offset: usize,
    pub sink_byte_offset: usize,
}

const MAX_ITERATIONS: usize = 100;

/// Forward dataflow taint analysis. Returns violations where a source (e.g. external call)
/// taints a path that reaches a sink (e.g. state write) without passing a sanitizer (e.g. guard).
pub fn find_taint_violations(cfg: &ControlFlowGraph, query: &TaintQuery) -> Vec<TaintViolation> {
    let sources: std::collections::HashSet<CfgStatementKind> =
        query.sources.iter().copied().collect();
    let sinks: std::collections::HashSet<CfgStatementKind> = query.sinks.iter().copied().collect();
    let sanitizers: std::collections::HashSet<CfgStatementKind> =
        query.sanitizers.iter().copied().collect();

    let mut in_state: HashMap<BasicBlockId, TaintState> = HashMap::new();
    let mut worklist: VecDeque<BasicBlockId> = VecDeque::new();
    worklist.push_back(cfg.entry);
    in_state.insert(cfg.entry, TaintState::default());

    let mut violations = Vec::new();
    let mut iterations = 0;

    while let Some(block_id) = worklist.pop_front() {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            break;
        }

        let block = match cfg.block(block_id) {
            Some(b) => b,
            None => continue,
        };
        let mut state = in_state.get(&block_id).copied().unwrap_or_default();

        // Entry block as source: taint all paths from function entry until sanitized.
        if block_id == cfg.entry && sources.contains(&CfgStatementKind::EntryBlock) {
            state.tainted = true;
            state.source_byte = 0;
            state.source_line = 0;
        }

        for stmt in &block.statements {
            let kind = kind_of(stmt);
            if sources.contains(&kind) {
                state.tainted = true;
                state.source_byte = byte_offset_of(stmt);
                state.source_line = line_of(stmt);
            } else if sanitizers.contains(&kind) {
                state.tainted = false;
                state.source_byte = 0;
                state.source_line = 0;
            }
            if sinks.contains(&kind) && state.tainted {
                violations.push(TaintViolation {
                    source_line: state.source_line,
                    sink_line: line_of(stmt),
                    source_byte_offset: state.source_byte,
                    sink_byte_offset: byte_offset_of(stmt),
                });
            }
        }

        for &succ in &block.successors {
            if succ == cfg.exit && sinks.contains(&CfgStatementKind::ExitBlock) && state.tainted {
                violations.push(TaintViolation {
                    source_line: state.source_line,
                    sink_line: 0,
                    source_byte_offset: state.source_byte,
                    sink_byte_offset: 0,
                });
            }
            let prev = in_state.get(&succ).copied();
            let merged = merge_state(prev.unwrap_or_default(), state);
            let should_push = match prev {
                None => true,
                Some(p) => merged.tainted != p.tainted || merged.source_byte != p.source_byte,
            };
            if should_push {
                in_state.insert(succ, merged);
                worklist.push_back(succ);
            }
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Tests: hand-built CFGs (no parsing dependency)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BasicBlock, BasicBlockId, CfgStatement, ControlFlowGraph, GuardKind};
    use smallvec::SmallVec;

    fn block(
        id: u32,
        statements: Vec<CfgStatement>,
        successors: Vec<u32>,
        predecessors: Vec<u32>,
    ) -> BasicBlock {
        BasicBlock {
            id: BasicBlockId(id as usize),
            statements,
            successors: successors
                .into_iter()
                .map(|u| BasicBlockId(u as usize))
                .collect::<SmallVec<[BasicBlockId; 2]>>(),
            predecessors: predecessors
                .into_iter()
                .map(|u| BasicBlockId(u as usize))
                .collect::<SmallVec<[BasicBlockId; 4]>>(),
        }
    }

    fn reentrancy_query() -> TaintQuery {
        TaintQuery {
            sources: vec![CfgStatementKind::ExternalCall],
            sinks: vec![CfgStatementKind::StateWrite],
            sanitizers: vec![CfgStatementKind::Guard],
        }
    }

    /// 1. Straight-line: source → sink, no sanitizer → tainted (one violation).
    #[test]
    fn straight_line_source_to_sink_no_sanitizer_tainted() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(2),
            blocks: vec![
                block(0, vec![], vec![1], vec![]),
                block(
                    1,
                    vec![
                        CfgStatement::ExternalCall {
                            byte_offset: 10,
                            line: 5,
                        },
                        CfgStatement::StateWrite {
                            byte_offset: 20,
                            line: 6,
                        },
                    ],
                    vec![2],
                    vec![0],
                ),
                block(2, vec![], vec![], vec![1]),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].source_line, 5);
        assert_eq!(violations[0].sink_line, 6);
    }

    /// 2. Straight-line: source → sanitizer → sink → not tainted.
    #[test]
    fn straight_line_sanitizer_clears_taint() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(3),
            blocks: vec![
                block(0, vec![], vec![1], vec![]),
                block(
                    1,
                    vec![CfgStatement::ExternalCall {
                        byte_offset: 10,
                        line: 5,
                    }],
                    vec![2],
                    vec![0],
                ),
                block(
                    2,
                    vec![CfgStatement::Guard {
                        byte_offset: 15,
                        kind: GuardKind::Require,
                    }],
                    vec![3],
                    vec![1],
                ),
                block(
                    3,
                    vec![CfgStatement::StateWrite {
                        byte_offset: 25,
                        line: 8,
                    }],
                    vec![],
                    vec![2],
                ),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert!(
            violations.is_empty(),
            "guard should clear taint; got {:?}",
            violations
        );
    }

    /// 3. Branching: source on one branch, sink on both → tainted only on source branch.
    #[test]
    fn branching_source_on_one_branch_sink_on_both() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(3),
            blocks: vec![
                block(0, vec![], vec![1, 2], vec![]),
                block(
                    1,
                    vec![
                        CfgStatement::ExternalCall {
                            byte_offset: 10,
                            line: 5,
                        },
                        CfgStatement::StateWrite {
                            byte_offset: 20,
                            line: 6,
                        },
                    ],
                    vec![3],
                    vec![0],
                ),
                block(
                    2,
                    vec![CfgStatement::StateWrite {
                        byte_offset: 30,
                        line: 10,
                    }],
                    vec![3],
                    vec![0],
                ),
                block(3, vec![], vec![], vec![1, 2]),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert_eq!(
            violations.len(),
            1,
            "only path with external call should violate"
        );
        assert_eq!(violations[0].source_line, 5);
    }

    /// 4. Loops: source in loop body → sink after loop → tainted (fixed-point converges).
    #[test]
    fn loop_source_in_body_sink_after_tainted() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(3),
            blocks: vec![
                block(0, vec![], vec![1], vec![]),
                block(1, vec![], vec![2, 3], vec![0, 2]), // loop head
                block(
                    2,
                    vec![CfgStatement::ExternalCall {
                        byte_offset: 10,
                        line: 7,
                    }],
                    vec![1],
                    vec![1],
                ),
                block(
                    3,
                    vec![CfgStatement::StateWrite {
                        byte_offset: 20,
                        line: 10,
                    }],
                    vec![],
                    vec![1],
                ),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert!(
            !violations.is_empty(),
            "path entry→1→2→1→3 has call then state write"
        );
    }

    /// 5. Unreachable blocks: source in dead code → not tainted.
    #[test]
    fn unreachable_block_source_not_tainted() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(2),
            blocks: vec![
                block(0, vec![], vec![1], vec![]),
                block(
                    1,
                    vec![CfgStatement::StateWrite {
                        byte_offset: 10,
                        line: 5,
                    }],
                    vec![2],
                    vec![0],
                ),
                block(2, vec![], vec![], vec![1]),
                block(
                    3,
                    vec![CfgStatement::ExternalCall {
                        byte_offset: 99,
                        line: 99,
                    }],
                    vec![],
                    vec![],
                ),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert!(violations.is_empty(), "block 3 unreachable from entry");
    }

    /// 6. Multiple sources on different paths reaching same sink.
    #[test]
    fn multiple_sources_same_sink() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(3),
            blocks: vec![
                block(0, vec![], vec![1, 2], vec![]),
                block(
                    1,
                    vec![
                        CfgStatement::ExternalCall {
                            byte_offset: 10,
                            line: 5,
                        },
                        CfgStatement::StateWrite {
                            byte_offset: 15,
                            line: 6,
                        },
                    ],
                    vec![3],
                    vec![0],
                ),
                block(
                    2,
                    vec![
                        CfgStatement::ExternalCall {
                            byte_offset: 20,
                            line: 8,
                        },
                        CfgStatement::StateWrite {
                            byte_offset: 25,
                            line: 9,
                        },
                    ],
                    vec![3],
                    vec![0],
                ),
                block(3, vec![], vec![], vec![1, 2]),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert_eq!(violations.len(), 2);
    }

    /// 7. Convergence bound: pathological loop does not hang, returns bounded result.
    #[test]
    fn convergence_bound_no_hang() {
        let cfg = ControlFlowGraph {
            entry: BasicBlockId(0),
            exit: BasicBlockId(1),
            blocks: vec![
                block(0, vec![], vec![0, 1], vec![0]), // self-loop + exit
                block(
                    1,
                    vec![CfgStatement::StateWrite {
                        byte_offset: 10,
                        line: 5,
                    }],
                    vec![],
                    vec![0],
                ),
            ],
        };
        let violations = find_taint_violations(&cfg, &reentrancy_query());
        assert!(
            violations.len() <= 2,
            "bounded iterations; may report 0 or some violations"
        );
    }
}
