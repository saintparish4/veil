# Detector Architecture

This directory contains all 13 vulnerability detectors for the Veil scanner.
Each detector is a zero-sized struct that implements the [`Detector`] trait
defined in `core/src/detector_trait.rs`.

---

## The `Detector` Trait

```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;                    // kebab-case, used in suppression rules
    fn name(&self) -> &'static str;                  // human-readable display name
    fn severity(&self) -> Severity;                  // default severity for findings
    fn owasp_category(&self) -> Option<&'static str>; // OWASP SC Top 10 category
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>);
}
```

Detectors receive an `AnalysisContext` (read-only) and append `Finding` values
to the shared `findings` vec. The context provides:

| Field | Type | Description |
|-------|------|-------------|
| `ctx.tree` | `&Tree` | Parsed tree-sitter AST |
| `ctx.source` | `&str` | Raw Solidity source |
| `ctx.file_path` | `Option<&str>` | File being scanned |
| `ctx.functions` | `Vec<Node>` | Pre-computed `function_definition` nodes |
| `ctx.cfg_for(func)` | `Option<Ref<CFG>>` | Lazy CFG for a function (cached) |

---

## Current Detectors

| File | Struct | `id` | Severity | AST Node Types Used |
|------|--------|------|----------|---------------------|
| `reentrancy.rs` | `ReentrancyDetector` | `reentrancy` | High | `call_expression`, `assignment_expression`, CFG taint |
| `unchecked_calls.rs` | `UncheckedCallsDetector` | `unchecked-call` | Medium | `call_expression`, `tuple_expression` |
| `tx_origin.rs` | `TxOriginDetector` | `tx-origin` | High | `member_expression` (tx.origin in binary_expression) |
| `access_control.rs` | `AccessControlDetector` | `access-control` | High | `call_expression`, `modifier_invocation`, `member_expression` |
| `delegatecall.rs` | `DangerousDelegatecallDetector` | `dangerous-delegatecall` | Critical | `call_expression`, `member_expression` (delegatecall) |
| `timestamp.rs` | `TimestampDetector` | `timestamp-dependence` | Medium | `member_expression` (block.timestamp) |
| `unsafe_random.rs` | `UnsafeRandomDetector` | `unsafe-randomness` | High | `member_expression` (block.prevrandao, blockhash) |
| `integer_overflow.rs` | `IntegerOverflowDetector` | `integer-overflow` | High | `pragma_directive`, `unchecked_statement` |
| `flash_loan.rs` | `FlashLoanDetector` | `flash-loan` | High | `function_definition` (callback names), `call_expression` |
| `storage_collision.rs` | `StorageCollisionDetector` | `storage-collision` | Critical | `state_variable_declaration` (__gap), `function_definition` (initializer) |
| `front_running.rs` | `FrontRunningDetector` | `front-running` | Medium | `call_expression` (approve/swap), parameter names |
| `dos_loops.rs` | `DosLoopsDetector` | `dos-loops` | High | `for_statement`, `while_statement`, `call_expression` |
| `unchecked_erc20.rs` | `UncheckedErc20Detector` | `unchecked-erc20` | High | `call_expression` (transfer/transferFrom/approve) |

---

## How to Add a New Detector

### 1. Create the detector file

```rust
// core/src/detectors/my_detector.rs
//! Detector: Short description of what this detects.
//!
//! Explanation of vulnerability and detection strategy.

use crate::ast_utils::find_nodes_of_kind;
use crate::detector_trait::{AnalysisContext, Detector};
use crate::types::{Confidence, Finding, Severity};

pub struct MyDetector;

impl Detector for MyDetector {
    fn id(&self) -> &'static str { "my-detector" }
    fn name(&self) -> &'static str { "My Vulnerability" }
    fn severity(&self) -> Severity { Severity::High }
    fn owasp_category(&self) -> Option<&'static str> {
        Some("SC01:2025 - Access Control Vulnerabilities")
    }

    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            // Walk AST nodes, not source text.
            let calls = find_nodes_of_kind(func, "call_expression");
            for call in calls {
                // Check structural properties of the node.
                if is_vulnerable_pattern(&call, ctx.source) {
                    findings.push(Finding::from_detector(
                        self,
                        call.start_position().row + 1,
                        Confidence::High,
                        "My Vulnerability",
                        format!("Description with context"),
                        "Suggested fix",
                    ));
                }
            }
        }
    }
}
```

### 2. Register the module

In `core/src/detectors/mod.rs`:

```rust
mod my_detector;
pub use my_detector::MyDetector;

// In build_registry():
Box::new(MyDetector),
```

### 3. Add test contracts

Add to `core/contracts/`:
- A **vulnerable** contract that the detector should flag.
- A **safe** contract (or safe pattern within the same file) that the detector
  should not flag.

### 4. Write tests

In `core/src/detectors/my_detector.rs` or `core/src/main.rs`:

```rust
#[test]
fn detector_my_detector_finds_vulnerable_pattern() {
    let source = r#"pragma solidity ^0.8.0; ..."#;
    let findings = run_detector(&MyDetector, source);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].vulnerability_type, "My Vulnerability");
}

#[test]
fn fp_absence_my_detector_safe_pattern() {
    let source = r#"pragma solidity ^0.8.0; ..."#;
    let findings = run_detector(&MyDetector, source);
    assert!(findings.is_empty(), "safe pattern should not trigger");
}
```

---

## Key Design Constraints

**Use AST nodes, not string matching.** All detectors traverse `tree_sitter::Node`
using helpers from `core/src/ast_utils.rs`. `str::contains()` on function text
is not acceptable — it cannot distinguish code from comments, string literals,
or multi-line expressions.

**CFG-aware detectors read from the CFG exclusively.** Detectors that use
`ctx.cfg_for(func)` (reentrancy, unchecked calls) do not also walk the raw AST
for the same function. The CFG builder (`core/src/cfg.rs`) classifies statements
once; detectors consume that classification.

**Use `Finding::from_detector`** to construct findings. This automatically
populates `detector_id`, `severity`, and `owasp_category` from the trait methods,
keeping findings consistent and reducing boilerplate.

**Suppression is handled by the scan layer.** Detectors do not need to check for
`// veil-ignore:` comments — `filter_findings_by_inline_ignores` in
`core/src/suppression.rs` removes suppressed findings after all detectors run.

**Confidence reflects certainty, not severity.** A critical vulnerability found
with low confidence (e.g. behind many conditions) should still be `Severity::Critical`
with `Confidence::Low`. Use `visibility_adjusted_confidence` from `helpers.rs`
to lower confidence for private/internal functions.

---

## AST Utility Reference (`core/src/ast_utils.rs`)

| Function | Purpose |
|----------|---------|
| `find_nodes_of_kind(root, kind)` | Collect all descendants of given node kind |
| `node_text(node, source)` | Extract source text for a node |
| `is_external_call(node, source)` | True if node is `.call`, `.transfer`, or `.send` |
| `is_state_write(node)` | True if node is a storage-mutating assignment |
| `get_call_target(node, source)` | Returns `CallTarget` enum (member call, free call, etc.) |
| `get_member_access(node, source)` | Returns `(object, property)` for `member_expression` |
| `function_modifiers(func, source)` | List of modifier names on a function |
| `function_visibility(func, source)` | `Visibility` enum from the AST `visibility` node |
| `has_reentrancy_guard(func, source)` | True if any modifier looks like a reentrancy guard |
| `has_access_control(func, source)` | True if function has ownership/sender check |
| `is_inside_unchecked_block(node)` | True if node is inside an `unchecked { }` block |
| `func_body(func)` | The `block` body node of a function, if present |
| `find_ancestor_of_kind(node, kind)` | Walk up the tree to find an ancestor of a given kind |
