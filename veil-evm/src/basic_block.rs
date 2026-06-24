//! Partition a flat instruction list into basic blocks.
//!
//! A new basic block begins at:
//! - Offset 0 (entry)
//! - Any `JUMPDEST` instruction (target of a jump)
//! - The instruction immediately following a terminator (JUMP, JUMPI, STOP, etc.)
//!
//! A basic block ends at the first terminator (inclusive).

use crate::disasm::Instruction;
use std::collections::HashSet;

/// A single EVM basic block: a maximal straight-line sequence of instructions.
#[derive(Debug, Clone)]
pub struct EvmBasicBlock {
    /// Byte offset of the first instruction in this block.
    pub start_offset: usize,
    /// Byte offset one past the last instruction (exclusive).
    pub end_offset: usize,
    /// The instructions in this block, in program order.
    pub instructions: Vec<Instruction>,
}

impl EvmBasicBlock {
    /// True if this block contains a `DELEGATECALL` instruction.
    pub fn has_delegatecall(&self) -> bool {
        self.instructions.iter().any(|i| i.is_delegatecall())
    }

    /// True if this block contains an `SSTORE` instruction.
    pub fn has_sstore(&self) -> bool {
        self.instructions.iter().any(|i| i.is_sstore())
    }

    /// True if this block contains any external call instruction.
    pub fn has_external_call(&self) -> bool {
        self.instructions.iter().any(|i| i.is_call())
    }

    /// The terminating instruction of this block, if it ends with one.
    pub fn terminator(&self) -> Option<&Instruction> {
        self.instructions.last().filter(|i| i.is_terminator())
    }
}

/// Partition `instructions` into basic blocks.
pub fn build_basic_blocks(instructions: &[Instruction]) -> Vec<EvmBasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }

    // Collect the offsets of all JUMPDEST instructions (block leaders).
    let jumpdests: HashSet<usize> = instructions
        .iter()
        .filter(|i| i.opcode == 0x5b)
        .map(|i| i.offset)
        .collect();

    let mut blocks = Vec::new();
    let mut current: Vec<Instruction> = Vec::new();
    let mut start_offset = instructions[0].offset;

    for instr in instructions {
        // JUMPDEST starts a new block (unless current is empty).
        if instr.opcode == 0x5b && !current.is_empty() {
            let end_offset = instr.offset;
            blocks.push(EvmBasicBlock {
                start_offset,
                end_offset,
                instructions: std::mem::take(&mut current),
            });
            start_offset = instr.offset;
        }

        let is_term = instr.is_terminator();
        current.push(instr.clone());

        // Terminator ends the current block.
        if is_term {
            let end_offset = instr.offset + 1;
            blocks.push(EvmBasicBlock {
                start_offset,
                end_offset,
                instructions: std::mem::take(&mut current),
            });
            // Next instruction starts a new block if it exists.
            // start_offset will be set at next iteration.
            if let Some(next) = instructions
                .iter()
                .find(|i| i.offset > instr.offset && !jumpdests.contains(&i.offset))
            {
                start_offset = next.offset;
            }
        }
    }

    // Flush any remaining instructions.
    if !current.is_empty() {
        let end_offset = current.last().map(|i| i.offset + 1).unwrap_or(start_offset);
        blocks.push(EvmBasicBlock {
            start_offset,
            end_offset,
            instructions: current,
        });
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;

    #[test]
    fn single_block_no_jumps() {
        // PUSH1 0x01, STOP
        let bytecode = [0x60, 0x01, 0x00];
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].terminator().is_some());
    }

    #[test]
    fn jumpdest_splits_blocks() {
        // PUSH1 0x03, JUMP, JUMPDEST (0x03), STOP
        let bytecode = [0x60, 0x03, 0x56, 0x5b, 0x00];
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        assert!(blocks.len() >= 2, "JUMPDEST should split blocks");
    }
}
