//! Scanning: parse Solidity, run detectors via [`DetectorRegistry`], apply suppressions.
//!
//! Returns `ScanOutcome` with both findings and errors (partial success).

use crate::detector_trait::{AnalysisContext, DetectorRegistry};
use crate::suppression;
use crate::types::{Finding, ScanError, ScanErrorKind, ScanOutcome, Severity, Statistics};
use rayon::prelude::*;
use std::cell::RefCell;
use std::fs;
use std::time::Instant;
use walkdir::WalkDir;

/// Create a new tree-sitter parser configured for Solidity.
pub fn new_solidity_parser() -> Result<tree_sitter::Parser, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_solidity::LANGUAGE.into())
        .map_err(|e| format!("Failed to load Solidity grammar: {}", e))?;
    Ok(parser)
}

// I keep one Parser per rayon worker thread because tree_sitter::Parser is !Send.
// The thread_local gives each worker its own instance with zero lock contention
thread_local! {
    static PARSER: RefCell<tree_sitter::Parser> =
    RefCell::new(new_solidity_parser().expect("Solidity grammar load failed at thread int"));
}

/// Scan a single file using the provided registry.
/// Returns `ScanOutcome` containing findings and any errors encountered.
pub fn scan_file_with(
    file_path: &str,
    registry: &DetectorRegistry,
    parser: &mut tree_sitter::Parser,
) -> ScanOutcome {
    let t0 = Instant::now();
    tracing::debug!(file = file_path, detectors = registry.len(), "scan start");

    let source = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(file = file_path, error = %e, "file read failed");
            return ScanOutcome {
                findings: Vec::new(),
                statistics: Statistics::default(),
                errors: vec![ScanError {
                    file: file_path.to_string(),
                    kind: ScanErrorKind::FileReadError,
                    message: e.to_string(),
                }],
            };
        }
    };

    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => {
            tracing::warn!(file = file_path, "tree-sitter parse returned None");
            return ScanOutcome {
                findings: Vec::new(),
                statistics: Statistics::default(),
                errors: vec![ScanError {
                    file: file_path.to_string(),
                    kind: ScanErrorKind::ParseError,
                    message: "tree-sitter returned None".to_string(),
                }],
            };
        }
    };

    let ctx = AnalysisContext::new(&tree, &source).with_file_path(file_path);
    let mut findings = Vec::new();
    registry.run_all(&ctx, &mut findings);

    for f in &mut findings {
        f.file = Some(file_path.to_string());
        f.compute_id();
    }

    let findings = suppression::filter_findings_by_inline_ignores(findings, &source);

    tracing::info!(
        file = file_path,
        total_findings = findings.len(),
        elapsed_ms = t0.elapsed().as_millis(),
        "scan complete"
    );

    let statistics = calculate_statistics(&findings);
    ScanOutcome {
        findings,
        statistics,
        errors: Vec::new(),
    }
}

/// Scan a directory (optionally recursive) using the provided registry
/// Files are scanned in parallel; each rayon worker uses its own thread-local Parser
/// Returns aggregated `ScanOutcome` across all files
pub fn scan_directory_with(
    dir_path: &str,
    recursive: bool,
    registry: &DetectorRegistry,
) -> ScanOutcome {
    let walker = if recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };

    // I collect paths first so rayon can divide the work evenly before any I/O starts
    let paths: Vec<String> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            p.is_file() && p.extension().is_some_and(|ext| ext == "sol")
        })
        .filter_map(|e| e.path().to_str().map(|s| s.to_string()))
        .collect();

    let partial_outcomes: Vec<ScanOutcome> = paths
        .par_iter()
        .map(|path_str| {
            // I borrow the thread-local parser mutably inside the closure
            // RefCell::borrow_mut() panics if called re-entrantly on the same thread,
            // but rayon never runs two tasks on the same thread simultaneously, so this is safe
            PARSER.with(|cell| {
                let mut parser = cell.borrow_mut();
                scan_file_with(path_str, registry, &mut parser)
            })
        })
        .collect();

    let mut outcome = ScanOutcome::default();
    for partial in partial_outcomes {
        outcome.findings.extend(partial.findings);
        outcome.errors.extend(partial.errors);
    }
    outcome
}

#[must_use]
pub fn calculate_statistics(findings: &[Finding]) -> Statistics {
    let mut stats = Statistics::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => stats.critical += 1,
            Severity::High => stats.high += 1,
            Severity::Medium => stats.medium += 1,
            Severity::Low => stats.low += 1,
        }
        match finding.confidence {
            crate::types::Confidence::High => stats.confidence_high += 1,
            crate::types::Confidence::Medium => stats.confidence_medium += 1,
            crate::types::Confidence::Low => stats.confidence_low += 1,
        }
    }

    stats
}

/// Map scan statistics to a process exit code.
/// 0 = clean, 1 = low/medium only, 2 = high, 3 = critical.
#[must_use]
pub fn exit_code_for_stats(stats: &Statistics) -> i32 {
    if stats.critical > 0 {
        3
    } else if stats.high > 0 {
        2
    } else if stats.medium > 0 || stats.low > 0 {
        1
    } else {
        0
    }
}
