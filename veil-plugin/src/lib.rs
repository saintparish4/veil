//! `veil-plugin` — public API for authoring custom veil detectors.
//!
//! Add this crate as a workspace member in your project's `Cargo.toml`:
//!
//! ```toml
//! # Your project's Cargo.toml
//! [workspace]
//! members = ["contracts", "my-detectors"]
//!
//! [workspace.dependencies]
//! veil-plugin = { git = "https://github.com/saintparish4/veil" }
//! ```
//!
//! Then implement [`Detector`] in `my-detectors/src/lib.rs`:
//!
//! ```rust,ignore
//! use veil_plugin::{AnalysisContext, Confidence, Detector, Finding, Severity};
//!
//! pub const VEIL_PLUGIN_API_VERSION: u32 = veil_plugin::API_VERSION;
//!
//! pub struct MyDetector;
//!
//! impl Detector for MyDetector {
//!     fn id(&self) -> &'static str { "my-custom-check" }
//!     fn name(&self) -> &'static str { "My Custom Check" }
//!     fn severity(&self) -> Severity { Severity::High }
//!     fn owasp_category(&self) -> Option<&'static str> { None }
//!
//!     fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
//!         for func in &ctx.functions {
//!             // analyse func using ctx.source, ctx.summaries, ctx.cfg_for(func), etc.
//!         }
//!     }
//! }
//! ```
//!
//! Register your detector by calling `registry.register(Box::new(MyDetector))` before scanning.

/// API version constant. Bump on breaking changes to the plugin interface.
/// External plugins should assert `veil_plugin::API_VERSION == EXPECTED_VERSION` at startup.
pub const API_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Re-exports — the complete public surface a plugin author needs
// ---------------------------------------------------------------------------

// Core analysis context + trait
pub use veil::detector_trait::{AnalysisContext, Detector, DetectorRegistry};

// Finding construction
pub use veil::types::{Confidence, Finding, Severity};

// CFG types (for detectors that perform custom dataflow)
pub use veil::cfg::{
    BasicBlock, BasicBlockId, CallKind, CallMeta, CfgStatement, ControlFlowGraph, GuardKind,
    StorageOp, StorageOpKind, StorageSlotExpr,
};

// Taint analysis (run custom source/sink/sanitizer queries)
pub use veil::taint::{find_taint_violations, CfgStatementKind, TaintQuery, TaintViolation};

// DeFi pattern helpers (classify protocol roles, detect flash-loan receivers, etc.)
pub use veil::defi_patterns::{
    classify_contract_role, has_cei_pattern, is_erc4626_vault, is_flash_loan_receiver,
    is_proxy_upgrade_function, is_uniswap_callback, ContractRole,
};

// Inter-procedural summaries
pub use veil::interprocedural::FunctionSummary;

// Storage layout model
pub use veil::storage_model::{build_storage_model, StorageModel, StorageSlot};

// AST utilities (walk the tree-sitter AST, classify nodes)
pub use veil::ast_utils::{
    find_nodes_of_kind, func_body, function_modifiers, function_name, get_call_target,
    is_external_call, is_state_write, is_view_or_pure, node_text, CallTarget,
};

// Pattern rule engine (parse/eval custom TOML predicate expressions)
pub use veil::rule_engine::{eval_predicate, parse_predicate, run_pattern_rules, PatternRule, Predicate};
