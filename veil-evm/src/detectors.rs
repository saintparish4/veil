//! EVM-level vulnerability detectors.
//!
//! These checks operate purely on disassembled bytecode and the EVM CFG,
//! finding vulnerabilities that are invisible at the Solidity AST level.
//!
//! Current detectors:
//! - `detect_delegatecall_from_storage` — DELEGATECALL whose target is loaded from storage
//! - `detect_unprotected_selfdestruct` — SELFDESTRUCT without any preceding conditional guard

use crate::cfg::EvmCfg;
use crate::disasm::Instruction;

// ---------------------------------------------------------------------------
// Finding type
// ---------------------------------------------------------------------------

/// A vulnerability finding from EVM bytecode analysis.
#[derive(Debug, Clone)]
pub struct EvmFinding {
    /// Stable detector identifier.
    pub detector_id: &'static str,
    /// Severity string: `"Critical"`, `"High"`, `"Medium"`, `"Low"`.
    pub severity: &'static str,
    /// Human-readable description of the finding.
    pub message: String,
    /// Byte offset of the offending instruction in the bytecode.
    pub bytecode_offset: usize,
    /// Source line number, if resolved via source map.
    pub line: Option<usize>,
    /// Source file path, if resolved via source map.
    pub file: Option<String>,
}

// ---------------------------------------------------------------------------
// Detector: DELEGATECALL from storage
// ---------------------------------------------------------------------------

/// Detect `DELEGATECALL` instructions whose target address was loaded from storage (`SLOAD`).
///
/// A proxy that stores its implementation address in a storage slot and calls `DELEGATECALL`
/// with that address is a valid pattern — but if the storage slot can be written by an
/// unprivileged caller, the implementation can be changed to arbitrary malicious code.
///
/// Detection heuristic: `SLOAD` within 8 instructions before a `DELEGATECALL` in the same block.
/// This is a conservative over-approximation; some matches may be false positives when the
/// loaded value is consumed before reaching the call target position on the stack.
pub fn detect_delegatecall_from_storage(cfg: &EvmCfg) -> Vec<EvmFinding> {
    let mut findings = Vec::new();

    for block in cfg.blocks.values() {
        for (i, instr) in block.instructions.iter().enumerate() {
            if !instr.is_delegatecall() {
                continue;
            }

            // Look back within the block for an SLOAD that may have provided the target address.
            // The DELEGATECALL stack args are: gas, to, argsOffset, argsLength, retOffset, retLength.
            // "to" is the 2nd argument pushed, so SLOAD within ~6 preceding instructions is suspicious.
            let window_start = i.saturating_sub(8);
            let has_sload = block.instructions[window_start..i]
                .iter()
                .any(|prev| prev.opcode == 0x54); // SLOAD

            if has_sload {
                findings.push(EvmFinding {
                    detector_id: "evm-delegatecall-from-storage",
                    severity: "Critical",
                    message: format!(
                        "DELEGATECALL at offset 0x{:x} uses a target address loaded from storage \
                         (SLOAD within 8 preceding instructions). If the storage slot is writable \
                         without access control, an attacker can redirect execution to arbitrary code.",
                        instr.offset
                    ),
                    bytecode_offset: instr.offset,
                    line: None,
                    file: None,
                });
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Detector: unprotected SELFDESTRUCT
// ---------------------------------------------------------------------------

/// Detect `SELFDESTRUCT` instructions that are not guarded by a conditional branch (`JUMPI`).
///
/// A `SELFDESTRUCT` without a preceding `JUMPI` within the look-back window may be callable
/// by anyone, permanently destroying the contract. False positives are possible when the
/// guarding `JUMPI` is in a different basic block (e.g. a modifier pattern).
pub fn detect_unprotected_selfdestruct(instructions: &[Instruction]) -> Vec<EvmFinding> {
    let mut findings = Vec::new();

    for (i, instr) in instructions.iter().enumerate() {
        if instr.opcode != 0xff {
            // SELFDESTRUCT
            continue;
        }

        let window_start = i.saturating_sub(20);
        let has_guard = instructions[window_start..i]
            .iter()
            .any(|prev| prev.opcode == 0x57); // JUMPI

        if !has_guard {
            findings.push(EvmFinding {
                detector_id: "evm-unprotected-selfdestruct",
                severity: "Critical",
                message: format!(
                    "SELFDESTRUCT at offset 0x{:x} has no conditional guard (JUMPI) in the \
                     preceding 20 instructions. If reachable by an unprivileged caller, \
                     this permanently destroys the contract.",
                    instr.offset
                ),
                bytecode_offset: instr.offset,
                line: None,
                file: None,
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic_block::build_basic_blocks;
    use crate::cfg::EvmCfg;
    use crate::disasm::disassemble;

    #[test]
    fn delegatecall_with_sload_flagged() {
        // SLOAD (0x54) followed by DELEGATECALL (0xf4)
        // Pad with NOPs (0x00) to simulate a realistic sequence.
        // PUSH1 gas, SLOAD target_slot, [args…], DELEGATECALL
        let bytecode = [
            0x60, 0x00, // PUSH1 0x00 (gas)
            0x54,       // SLOAD (load target from slot 0)
            0x60, 0x00, // PUSH1 0x00 (argsOffset)
            0x60, 0x00, // PUSH1 0x00 (argsLength)
            0x60, 0x00, // PUSH1 0x00 (retOffset)
            0x60, 0x00, // PUSH1 0x00 (retLength)
            0xf4,       // DELEGATECALL
            0x00,       // STOP
        ];
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        let cfg = EvmCfg::build(blocks);
        let findings = detect_delegatecall_from_storage(&cfg);
        assert!(!findings.is_empty(), "SLOAD before DELEGATECALL should be flagged");
        assert_eq!(findings[0].detector_id, "evm-delegatecall-from-storage");
        assert_eq!(findings[0].severity, "Critical");
    }

    #[test]
    fn delegatecall_without_sload_not_flagged() {
        // PUSH20 <address>, DELEGATECALL — target is a hardcoded constant, not from storage
        let mut bytecode = vec![0x73]; // PUSH20
        bytecode.extend_from_slice(&[0xaau8; 20]); // 20-byte address
        bytecode.extend_from_slice(&[0xf4, 0x00]); // DELEGATECALL, STOP
        let instrs = disassemble(&bytecode);
        let blocks = build_basic_blocks(&instrs);
        let cfg = EvmCfg::build(blocks);
        let findings = detect_delegatecall_from_storage(&cfg);
        assert!(
            findings.is_empty(),
            "hardcoded DELEGATECALL target should not be flagged"
        );
    }

    #[test]
    fn selfdestruct_without_guard_flagged() {
        let bytecode = [
            0x60, 0x00, // PUSH1 0x00
            0xff,       // SELFDESTRUCT
        ];
        let instrs = disassemble(&bytecode);
        let findings = detect_unprotected_selfdestruct(&instrs);
        assert!(!findings.is_empty(), "SELFDESTRUCT without guard should be flagged");
        assert_eq!(findings[0].severity, "Critical");
    }

    #[test]
    fn selfdestruct_with_jumpi_guard_not_flagged() {
        // JUMPI within 20 instructions before SELFDESTRUCT → guarded
        let bytecode = [
            0x60, 0x05, // PUSH1 dest
            0x60, 0x01, // PUSH1 condition=1
            0x57,       // JUMPI
            0x5b,       // JUMPDEST
            0x60, 0x00, // PUSH1 0x00
            0xff,       // SELFDESTRUCT
        ];
        let instrs = disassemble(&bytecode);
        let findings = detect_unprotected_selfdestruct(&instrs);
        assert!(
            findings.is_empty(),
            "SELFDESTRUCT with preceding JUMPI should not be flagged"
        );
    }
}
