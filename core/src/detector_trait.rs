//! Detector trait, AnalysisContext, and DetectorRegistry.
//!
//! Every vulnerability detector implements the [`Detector`] trait, which gives it a
//! machine-readable `id`, a human-readable `name`, a default `severity`, and an
//! optional OWASP category. Detectors are collected in a [`DetectorRegistry`] that is
//! built once at startup and shared for the lifetime of the process.
//!
//! [`AnalysisContext`] is the read-only bundle passed to each [`Detector::run`] call.
//! Phase S3 extends it with a lazy CFG cache; detectors that call [`AnalysisContext::cfg_for`]
//! get a CFG per function on demand; others pay zero cost.

use crate::ast_utils::find_nodes_of_kind;
use crate::cfg::ControlFlowGraph;
use crate::types::{Confidence, Finding, Severity};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;
use tree_sitter::{Node, Tree};

// ---------------------------------------------------------------------------
// AnalysisContext
// ---------------------------------------------------------------------------

/// Everything a detector needs to analyse one Solidity file.
///
/// Passed by reference to [`Detector::run`]; detectors only read from it.
/// CFGs are built lazily per function via [`AnalysisContext::cfg_for`]; detectors
/// that do not call it pay no CFG cost.
pub struct AnalysisContext<'a> {
    /// The fully parsed tree-sitter syntax tree for the file.
    pub tree: &'a Tree,
    /// Raw Solidity source bytes (UTF-8).
    pub source: &'a str,
    /// Path to the file being analysed, if known.
    pub file_path: Option<&'a str>,
    /// Pre-computed `function_definition` nodes for efficient iteration.
    pub functions: Vec<Node<'a>>,
    /// Lazy CFG cache keyed by function byte offset; only functions that request
    /// a CFG get one built and cached.
    cfgs: RefCell<HashMap<usize, ControlFlowGraph>>,
}

impl<'a> AnalysisContext<'a> {
    /// Construct a context from the minimal required fields.
    ///
    /// Pre-computes the list of `function_definition` nodes so detectors can
    /// iterate `ctx.functions` instead of traversing the full tree.
    pub fn new(tree: &'a Tree, source: &'a str) -> Self {
        let functions = find_nodes_of_kind(&tree.root_node(), "function_definition");
        Self {
            tree,
            source,
            file_path: None,
            functions,
            cfgs: RefCell::new(HashMap::new()),
        }
    }

    /// Returns a reference to the CFG for the given function, building and caching it on first use.
    /// Only builds CFGs for functions that request one; detectors that never call this pay zero cost.
    /// Returns `None` if the CFG cannot be built (e.g. abstract/interface, inline assembly).
    pub fn cfg_for(&self, func: &Node<'a>) -> Option<std::cell::Ref<'_, ControlFlowGraph>> {
        let key = func.start_byte();
        if !self.cfgs.borrow().contains_key(&key) {
            if let Some(cfg) = ControlFlowGraph::build_for_function(self.tree, self.source, func) {
                self.cfgs.borrow_mut().insert(key, cfg);
            }
        }
        let guard = self.cfgs.borrow();
        if guard.contains_key(&key) {
            Some(std::cell::Ref::map(guard, |m| {
                m.get(&key)
                    .expect("key was inserted above; map is not mutated between insert and borrow")
            }))
        } else {
            None
        }
    }

    /// Attach a file path (used for file-scoped analyses and error messages).
    pub fn with_file_path(mut self, path: &'a str) -> Self {
        self.file_path = Some(path);
        self
    }
}

// ---------------------------------------------------------------------------
// Finding builder (avoids circular dep between types.rs ↔ detector_trait.rs)
// ---------------------------------------------------------------------------

impl Finding {
    /// Construct a `Finding` that derives `detector_id`, `severity`, and
    /// `owasp_category` from the detector that produced it.
    pub fn from_detector(
        detector: &dyn Detector,
        line: usize,
        confidence: Confidence,
        vulnerability_type: &str,
        message: String,
        suggestion: &str,
    ) -> Self {
        Self {
            id: String::new(),
            detector_id: detector.id().to_string(),
            severity: detector.severity(),
            confidence,
            line,
            vulnerability_type: vulnerability_type.to_string(),
            message,
            suggestion: suggestion.to_string(),
            remediation: None,
            owasp_category: detector.owasp_category().map(|s| s.to_string()),
            file: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Detector trait
// ---------------------------------------------------------------------------

/// A self-describing vulnerability detector.
///
/// Implementations are zero-sized structs; all state lives in `AnalysisContext`.
/// The trait is object-safe so detectors can be collected as `Box<dyn Detector>`.
pub trait Detector: Send + Sync {
    /// Stable, kebab-case identifier (e.g. `"reentrancy"`, `"tx-origin"`).
    /// Used in suppression rules, baselines, and CI output.
    fn id(&self) -> &'static str;

    /// Human-readable display name (e.g. `"Reentrancy"`, `"tx.origin Authentication"`).
    fn name(&self) -> &'static str;

    /// Default severity for findings emitted by this detector.
    /// Individual findings may override this when context warrants it.
    fn severity(&self) -> Severity;

    /// OWASP Smart Contract Top 10 category, if applicable.
    fn owasp_category(&self) -> Option<&'static str>;

    /// Run the detector against the provided context and append any findings.
    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>);
}

// ---------------------------------------------------------------------------
// DetectorRegistry
// ---------------------------------------------------------------------------

/// An ordered collection of detectors run against every scanned file.
///
/// Build once (e.g. via [`DetectorRegistry::with_all_detectors`]) and share
/// across threads. Each entry is a heap-allocated trait object; the actual
/// detector structs are zero-sized so the only cost is the vtable pointer.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Build a registry from an explicit list of detectors.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// All registered detectors in run order.
    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Returns `true` if no detectors are registered.
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Run every detector and append findings to `findings`.
    ///
    /// Emits a `DEBUG` tracing event per detector reporting finding count and
    /// elapsed time. These are no-ops when no tracing subscriber is installed.
    pub fn run_all(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        let file = ctx.file_path.unwrap_or("<unknown>");
        for detector in &self.detectors {
            let t0 = Instant::now();
            let before = findings.len();
            detector.run(ctx, findings);
            tracing::debug!(
                detector = detector.id(),
                file = file,
                findings = findings.len() - before,
                elapsed_ms = t0.elapsed().as_millis(),
                "detector complete"
            );
        }
    }
}
