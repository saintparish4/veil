//! Raw EVM bytecode → `Vec<(byte_offset, Opcode)>`.
//!
//! Iterates the bytecode stream sequentially; PUSH instructions consume their
//! immediate operand bytes so that the next opcode starts at the correct offset.

/// A single decoded EVM opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Byte offset in the bytecode.
    pub offset: usize,
    /// Opcode value (0x00–0xff).
    pub opcode: u8,
    /// Mnemonic (e.g. `"PUSH1"`, `"SSTORE"`, `"DELEGATECALL"`).
    pub mnemonic: &'static str,
    /// Immediate bytes for PUSH1–PUSH32 instructions; empty for all others.
    pub immediate: Vec<u8>,
}

/// Decode raw bytecode into a flat instruction list.
///
/// Stops at the first invalid byte (i.e. the runtime code ends and data begins).
/// Callers should strip the Solidity metadata suffix before calling this function.
pub fn disassemble(bytecode: &[u8]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < bytecode.len() {
        let offset = i;
        let op = bytecode[i];
        i += 1;

        let (mnemonic, push_len) = decode_opcode(op);

        let immediate = if push_len > 0 {
            let end = (i + push_len).min(bytecode.len());
            let imm = bytecode[i..end].to_vec();
            i += push_len;
            imm
        } else {
            Vec::new()
        };

        instructions.push(Instruction {
            offset,
            opcode: op,
            mnemonic,
            immediate,
        });
    }

    instructions
}

/// Return `(mnemonic, push_immediate_length)` for an EVM opcode byte.
///
/// Returns `("INVALID", 0)` for undefined opcodes.
fn decode_opcode(op: u8) -> (&'static str, usize) {
    match op {
        0x00 => ("STOP", 0),
        0x01 => ("ADD", 0),
        0x02 => ("MUL", 0),
        0x03 => ("SUB", 0),
        0x04 => ("DIV", 0),
        0x05 => ("SDIV", 0),
        0x06 => ("MOD", 0),
        0x07 => ("SMOD", 0),
        0x08 => ("ADDMOD", 0),
        0x09 => ("MULMOD", 0),
        0x0a => ("EXP", 0),
        0x0b => ("SIGNEXTEND", 0),
        0x10 => ("LT", 0),
        0x11 => ("GT", 0),
        0x12 => ("SLT", 0),
        0x13 => ("SGT", 0),
        0x14 => ("EQ", 0),
        0x15 => ("ISZERO", 0),
        0x16 => ("AND", 0),
        0x17 => ("OR", 0),
        0x18 => ("XOR", 0),
        0x19 => ("NOT", 0),
        0x1a => ("BYTE", 0),
        0x1b => ("SHL", 0),
        0x1c => ("SHR", 0),
        0x1d => ("SAR", 0),
        0x20 => ("SHA3", 0),
        0x30 => ("ADDRESS", 0),
        0x31 => ("BALANCE", 0),
        0x32 => ("ORIGIN", 0),
        0x33 => ("CALLER", 0),
        0x34 => ("CALLVALUE", 0),
        0x35 => ("CALLDATALOAD", 0),
        0x36 => ("CALLDATASIZE", 0),
        0x37 => ("CALLDATACOPY", 0),
        0x38 => ("CODESIZE", 0),
        0x39 => ("CODECOPY", 0),
        0x3a => ("GASPRICE", 0),
        0x3b => ("EXTCODESIZE", 0),
        0x3c => ("EXTCODECOPY", 0),
        0x3d => ("RETURNDATASIZE", 0),
        0x3e => ("RETURNDATACOPY", 0),
        0x3f => ("EXTCODEHASH", 0),
        0x40 => ("BLOCKHASH", 0),
        0x41 => ("COINBASE", 0),
        0x42 => ("TIMESTAMP", 0),
        0x43 => ("NUMBER", 0),
        0x44 => ("DIFFICULTY", 0),
        0x45 => ("GASLIMIT", 0),
        0x46 => ("CHAINID", 0),
        0x47 => ("SELFBALANCE", 0),
        0x48 => ("BASEFEE", 0),
        0x50 => ("POP", 0),
        0x51 => ("MLOAD", 0),
        0x52 => ("MSTORE", 0),
        0x53 => ("MSTORE8", 0),
        0x54 => ("SLOAD", 0),
        0x55 => ("SSTORE", 0),
        0x56 => ("JUMP", 0),
        0x57 => ("JUMPI", 0),
        0x58 => ("PC", 0),
        0x59 => ("MSIZE", 0),
        0x5a => ("GAS", 0),
        0x5b => ("JUMPDEST", 0),
        0x5f => ("PUSH0", 0),
        op @ 0x60..=0x7f => ("PUSH", (op - 0x60 + 1) as usize),
        op @ 0x80..=0x8f => {
            let _ = op;
            ("DUP", 0)
        }
        op @ 0x90..=0x9f => {
            let _ = op;
            ("SWAP", 0)
        }
        op @ 0xa0..=0xa4 => {
            let _ = op;
            ("LOG", 0)
        }
        0xf0 => ("CREATE", 0),
        0xf1 => ("CALL", 0),
        0xf2 => ("CALLCODE", 0),
        0xf3 => ("RETURN", 0),
        0xf4 => ("DELEGATECALL", 0),
        0xf5 => ("CREATE2", 0),
        0xfa => ("STATICCALL", 0),
        0xfd => ("REVERT", 0),
        0xfe => ("INVALID", 0),
        0xff => ("SELFDESTRUCT", 0),
        _ => ("INVALID", 0),
    }
}

impl Instruction {
    /// True for opcodes that terminate basic blocks: JUMP, JUMPI, STOP, RETURN, REVERT,
    /// INVALID, SELFDESTRUCT.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self.opcode,
            0x00 | 0x56 | 0x57 | 0xf3 | 0xfd | 0xfe | 0xff
        )
    }

    /// True when this instruction is a `DELEGATECALL` (opcode 0xf4).
    pub fn is_delegatecall(&self) -> bool {
        self.opcode == 0xf4
    }

    /// True when this instruction is any external call (CALL/CALLCODE/DELEGATECALL/STATICCALL).
    pub fn is_call(&self) -> bool {
        matches!(self.opcode, 0xf1 | 0xf2 | 0xf4 | 0xfa)
    }

    /// True when this instruction writes storage (SSTORE).
    pub fn is_sstore(&self) -> bool {
        self.opcode == 0x55
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disasm_simple_sequence() {
        // PUSH1 0x60, PUSH1 0x40, MSTORE, STOP
        let bytecode = [0x60, 0x60, 0x60, 0x40, 0x52, 0x00];
        let instrs = disassemble(&bytecode);
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].mnemonic, "PUSH");
        assert_eq!(instrs[0].immediate, vec![0x60]);
        assert_eq!(instrs[1].mnemonic, "PUSH");
        assert_eq!(instrs[1].immediate, vec![0x40]);
        assert_eq!(instrs[2].mnemonic, "MSTORE");
        assert_eq!(instrs[3].mnemonic, "STOP");
        assert!(instrs[3].is_terminator());
    }

    #[test]
    fn disasm_delegatecall_detected() {
        let bytecode = [0xf4]; // DELEGATECALL
        let instrs = disassemble(&bytecode);
        assert_eq!(instrs[0].mnemonic, "DELEGATECALL");
        assert!(instrs[0].is_delegatecall());
        assert!(instrs[0].is_call());
    }

    #[test]
    fn disasm_sstore() {
        let bytecode = [0x55];
        let instrs = disassemble(&bytecode);
        assert!(instrs[0].is_sstore());
    }
}
