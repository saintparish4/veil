//! `veil-evm` — EVM bytecode frontend for veil.
//!
//! Analyses compiled EVM bytecode to surface vulnerabilities invisible at the
//! Solidity AST level, then correlates findings with source locations via the
//! Solidity compiler's source map.
//!
//! # Planned use case
//!
//! ```text
//! veil scan --bytecode MyContract.bin --sourcemap MyContract.json contracts/
//! ```
//!
//! This unlocks checks like:
//! - `DELEGATECALL` to a target read from an unprotected storage slot
//! - Storage layout collisions between proxy and implementation at the byte level
//! - Arithmetic overflow in pre-0.8 bytecode (no Solidity-level SafeMath)
//!
//! # Architecture
//!
//! ```text
//! bytecode bytes
//!     └─ disasm.rs ──────── Vec<(offset, Opcode)>
//!          └─ basic_block.rs ─ Vec<EvmBasicBlock>
//!               └─ cfg.rs ──── EvmCfg
//!                    └─ bridge.rs ── Correlate offset → (file, line)
//!                         └─ source_map.rs ── parse solc source-map JSON
//! ```

pub mod basic_block;
pub mod bridge;
pub mod cfg;
pub mod detectors;
pub mod disasm;
pub mod source_map;
