//! Veil — Smart Contract Security Scanner (library).
//!
//! Modules: types, helpers, suppression, detectors, scan, output (always available).

// Forbid silent panics from `.unwrap()` throughout library code.
// Use `.expect("reason")` to document invariants, or propagate errors explicitly.
// Test modules are exempt via `#[allow(clippy::unwrap_used)]` where needed.
#![deny(clippy::unwrap_used)]

pub mod ast_utils;
pub mod cfg;
pub mod detector_trait;
pub mod detectors;
pub mod helpers;
pub mod output;
pub mod report;
pub mod scan;
pub mod suppression;
pub mod taint;
pub mod types;

// --- Re-exports (always available) ------------------------------------------

pub use detector_trait::{AnalysisContext, Detector, DetectorRegistry};
pub use helpers::*;
pub use output::{format_json, format_sarif};
pub use report::{HtmlReport, PdfReport, ReportConfig, ReportError, ReportGenerator};
pub use scan::{calculate_statistics, scan_directory_with, scan_file_with};
pub use suppression::{
    filter_findings_by_baseline, filter_findings_by_inline_ignores, load_baseline,
    parse_veil_ignores, BaselineFile,
};
pub use types::{
    Confidence, Finding, ScanError, ScanErrorKind, ScanOutcome, Severity, Statistics, Visibility,
};

// --- Re-exports (CLI-only) --------------------------------------------------

#[cfg(feature = "cli")]
pub use output::{format_terminal, print_json, print_results, print_sarif};
