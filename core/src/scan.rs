//! Scanning: parse Solidity, run detectors via [`DetectorRegistry`], apply suppressions.
//!
//! Returns `ScanOutcome` with both findings and errors (partial success).

use crate::detector_trait::{AnalysisContext, DetectorRegistry};
use crate::suppression;
use crate::types::{Finding, ScanError, ScanErrorKind, ScanOutcome, Severity, Statistics};
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

/// Scan a single file using the provided registry.
/// Returns `ScanOutcome` containing findings and any errors encountered.
#[must_use]
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

/// Scan a directory (optionally recursive) using a shared parser and registry.
/// Returns aggregated `ScanOutcome` across all files.
#[must_use]
pub fn scan_directory_with(
    dir_path: &str,
    recursive: bool,
    registry: &DetectorRegistry,
    parser: &mut tree_sitter::Parser,
) -> ScanOutcome {
    let walker = if recursive {
        WalkDir::new(dir_path)
    } else {
        WalkDir::new(dir_path).max_depth(1)
    };
    let mut outcome = ScanOutcome::default();
    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() && p.extension().is_some_and(|e| e == "sol") {
            let path_str = p.to_str().unwrap_or_default();
            let file_outcome = scan_file_with(path_str, registry, parser);
            outcome.findings.extend(file_outcome.findings);
            outcome.errors.extend(file_outcome.errors);
        }
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
