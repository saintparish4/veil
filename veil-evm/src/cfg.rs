//! EVM-level control flow graph.
//!
//! Connects basic blocks by analysing JUMP/JUMPI targets.
//! Static JUMP targets can be recovered when preceded by a PUSH of the target offset;
//! dynamic jumps (computed targets) are conservatively left unresolved.

use crate::basic_block::EvmBasicBlock;
use std::collections::HashMap;

/// The EVM CFG: a map from block start-offset to successor offsets.
#[derive(Debug, Default)]
pub struct EvmCfg {
    /// All basic blocks, keyed by their start offset.
    pub blocks: HashMap<usize, EvmBasicBlock>,
    /// Edges: `start_offset → Vec<successor_start_offset>`.
    pub edges: HashMap<usize, Vec<usize>>,
}

impl EvmCfg {
    /// Build an EVM CFG from a flat list of basic blocks.
    pub fn build(blocks: Vec<EvmBasicBlock>) -> Self {
        let block_map: HashMap<usize, EvmBasicBlock> = blocks
            .into_iter()
            .map(|b| (b.start_offset, b))
            .collect();

        let mut edges: HashMap<usize, Vec<usize>> = HashMap::new();

        // Collect all JUMPDEST offsets (valid jump targets).
        let jumpdests: std::collections::HashSet<usize> =
            block_map.keys().copied().collect();

        for (offset, block) in &block_map {
            let succs = successors_of(block, &jumpdests);
            edges.insert(*offset, succs);
        }

        Self { blocks: block_map, edges }
    }

    /// Returns all blocks that contain a `DELEGATECALL` instruction.
    pub fn delegatecall_blocks(&self) -> Vec<&EvmBasicBlock> {
        self.blocks
            .values()
            .filter(|b| b.has_delegatecall())
            .collect()
    }

    /// Returns all blocks that write storage (`SSTORE`).
    pub fn sstore_blocks(&self) -> Vec<&EvmBasicBlock> {
        self.blocks.values().filter(|b| b.has_sstore()).collect()
    }
}

/// Compute successor offsets for a basic block.
fn successors_of(block: &EvmBasicBlock, jumpdests: &std::collections::HashSet<usize>) -> Vec<usize> {
    let mut succs = Vec::new();

    let Some(term) = block.terminator() else {
        // No terminator — falls through to the next block.
        // We conservatively add no edges; the caller can resolve fall-throughs separately.
        return succs;
    };

    match term.opcode {
        0x56 => {
            // JUMP: unconditional. Try to resolve static target from preceding PUSH.
            if let Some(target) = static_jump_target(block) {
                if jumpdests.contains(&target) {
                    succs.push(target);
                }
            }
            // Dynamic target: unresolved — succs stays empty (over-approximation of reachability).
        }
        0x57 => {
            // JUMPI: conditional. Resolves both the jump target and fall-through.
            if let Some(target) = static_jump_target(block) {
                if jumpdests.contains(&target) {
                    succs.push(target);
                }
            }
            // Fall-through = instruction after the JUMPI.
            let fallthrough = term.offset + 1;
            if jumpdests.contains(&fallthrough) {
                succs.push(fallthrough);
            }
        }
        // STOP, RETURN, REVERT, INVALID, SELFDESTRUCT → no successors
        _ => {}
    }

    succs
}

/// Try to extract the static jump target from a PUSH immediately before a JUMP/JUMPI.
fn static_jump_target(block: &EvmBasicBlock) -> Option<usize> {
    let instrs = &block.instructions;
    // The instruction before the terminator should be a PUSH.
    if instrs.len() < 2 {
        return None;
    }
    let push = &instrs[instrs.len() - 2];
    if push.mnemonic != "PUSH" || push.immediate.is_empty() {
        return None;
    }
    // Interpret the immediate as a big-endian integer.
    let mut target: usize = 0;
    for byte in &push.immediate {
        target = (target << 8) | (*byte as usize);
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic_block::build_basic_blocks;
    use crate::disasm::disassemble;

    #[test]
    fn cfg_single_block() {
        let bytecode = [0x60, 0x01, 0x00]; // PUSH1 0x01, STOP
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        let cfg = EvmCfg::build(blocks);
        assert_eq!(cfg.blocks.len(), 1);
    }

    #[test]
    fn delegatecall_blocks_found() {
        let bytecode = [0xf4, 0x00]; // DELEGATECALL, STOP
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        let cfg = EvmCfg::build(blocks);
        assert_eq!(cfg.delegatecall_blocks().len(), 1);
    }
}
