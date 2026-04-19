//! Detector: Storage collision in proxy / upgradeable contracts.
//!
//! Flags missing storage gaps, unprotected initializers, constructors in
//! upgradeable contracts, and non-EIP-1967 storage slot access.
//! Uses AST contract_declaration and function_definition nodes.

use crate::ast_utils::{find_nodes_of_kind, func_body, is_proxy_contract, node_text};
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct StorageCollisionDetector;

impl Detector for StorageCollisionDetector {
    fn id(&self) -> &'static str {
        "storage-collision"
    }
    fn name(&self) -> &'static str {
        "Storage Collision"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC08:2025 - Insecure Smart Contract Composition")
    }
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let root = ctx.tree.root_node();
        if !is_proxy_contract(&root, ctx.source) {
            return;
        }

        let contracts = find_nodes_of_kind(&root, "contract_declaration");
        for contract in &contracts {
            let contract_text = node_text(contract, ctx.source);
            let line = contract.start_position().row + 1;

            let has_state_vars = contract_text.contains("uint256 ")
                || contract_text.contains("address ")
                || contract_text.contains("mapping(")
                || contract_text.contains("bool ");

            let has_storage_gap = contract_text.contains("__gap")
                || contract_text.contains("uint256[")
                || contract_text.contains("bytes32[");

            let is_upgradeable = contract_text.contains("Upgradeable")
                || contract_text.contains("UUPS")
                || contract_text.contains("Transparent");

            // Pattern 1: Missing storage gap
            if has_state_vars && is_upgradeable && !has_storage_gap {
                findings.push(Finding::from_detector(
                    self,
                    line,
                    Confidence::Medium,
                    "Missing Storage Gap",
                    "Upgradeable contract without storage gap for future variables".to_string(),
                    "Add uint256[50] private __gap; at the end of storage variables",
                ));
            }

            // Pattern 2: Initializer without initialized flag
            if contract_text.contains("initialize")
                && !contract_text.contains("initializer")
                && !contract_text.contains("_initialized")
            {
                findings.push(Finding {
                    id: String::new(),
                    detector_id: self.id().to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Medium,
                    line,
                    vulnerability_type: "Unprotected Initializer".to_string(),
                    message: "Initialize function without initializer modifier".to_string(),
                    suggestion: "Use OpenZeppelin's Initializable and add initializer modifier"
                        .to_string(),
                    remediation: None,
                    owasp_category: self.owasp_category().map(|s| s.to_string()),
                    file: None,
                });
            }

            // Pattern 3: Constructor in upgradeable contract
            if is_upgradeable && contract_text.contains("constructor") {
                let constructor_has_logic = !contract_text.contains("constructor()")
                    || contract_text.contains("constructor(")
                        && !contract_text.contains("constructor() {");

                if constructor_has_logic {
                    findings.push(Finding::from_detector(
                        self,
                        line,
                        Confidence::High,
                        "Constructor in Proxy",
                        "Upgradeable contract with constructor logic (won't execute for proxy)"
                            .to_string(),
                        "Move constructor logic to initialize() function",
                    ));
                }
            }
        }

        // Pattern 4: Direct storage slot access without EIP-1967
        for func in &ctx.functions {
            let body = match func_body(func) {
                Some(b) => b,
                None => continue,
            };
            let body_text = node_text(&body, ctx.source);

            if body_text.contains("sstore") || body_text.contains("sload") {
                let uses_eip1967 = body_text.contains("0x360894")
                    || body_text.contains("0xb53127")
                    || body_text.contains("0x7050c9");

                if !uses_eip1967 {
                    findings.push(Finding {
                        id: String::new(),
                        detector_id: self.id().to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        line: func.start_position().row + 1,
                        vulnerability_type: "Non-Standard Storage Slot".to_string(),
                        message: "Direct storage access without EIP-1967 standard slots"
                            .to_string(),
                        suggestion: "Use EIP-1967 standard slots for proxy storage".to_string(),
                        remediation: None,
                        owasp_category: self.owasp_category().map(|s| s.to_string()),
                        file: None,
                    });
                }
            }
        }
    }
}
