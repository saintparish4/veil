//! Audit diff mode: compare two JSON scan outputs to surface new vs fixed findings.
//!
//! `veil diff before.json after.json` reads two scan results, identifies findings
//! that are new (in `after` but not `before`) and findings that were fixed (in
//! `before` but not `after`), and emits a structured summary with a risk delta.
//!
//! Finding identity: `Finding.id` (SHA-256 of `file:line:detector_id`, 16 hex chars).
//! Risk score: `critical×100 + high×10 + medium×3 + low×1`, summed across all findings,
//! with a confidence multiplier (High=1.0, Medium=0.67, Low=0.33).

use crate::types::{Confidence, Finding, Severity, Statistics};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ScanDiff {
    pub new_findings: Vec<Finding>,
    pub fixed_findings: Vec<Finding>,
    pub unchanged_count: usize,
    pub risk_delta: RiskDelta,
}

#[derive(Debug, Serialize)]
pub struct RiskDelta {
    pub before: i64,
    pub after: i64,
    pub delta: i64,
    pub assessment: String,
}

// ---------------------------------------------------------------------------
// Input (deserialize scan JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ScanOutput {
    findings: Vec<Finding>,
    #[allow(dead_code)] // field present in JSON schema but not used for diffing
    #[serde(default)]
    statistics: Statistics,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load a scan JSON file produced by `veil scan --format json`.
///
/// Returns `Err` with a human-readable message on parse/IO failure.
pub fn load_scan_json(path: &str) -> Result<Vec<Finding>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;
    let output: ScanOutput = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON in '{}': {}", path, e))?;
    Ok(output.findings)
}

/// Compare two sets of findings and return the diff.
///
/// Identity is based on `Finding.id`; findings with an empty id are matched
/// by `(file, line, detector_id)` tuple as a fallback (older scan outputs).
pub fn diff_scans(before: &[Finding], after: &[Finding]) -> ScanDiff {
    let before_ids = id_set(before);
    let after_ids = id_set(after);

    let new_findings: Vec<Finding> = after
        .iter()
        .filter(|f| {
            let id = effective_id(f);
            !before_ids.contains(id.as_str())
        })
        .cloned()
        .collect();

    let fixed_findings: Vec<Finding> = before
        .iter()
        .filter(|f| {
            let id = effective_id(f);
            !after_ids.contains(id.as_str())
        })
        .cloned()
        .collect();

    let unchanged_count = after.len().saturating_sub(new_findings.len());

    let risk_before = risk_score(before);
    let risk_after = risk_score(after);
    let delta = risk_after - risk_before;

    let assessment = match delta.cmp(&0) {
        std::cmp::Ordering::Less => "improved".to_string(),
        std::cmp::Ordering::Equal => "unchanged".to_string(),
        std::cmp::Ordering::Greater => "regressed".to_string(),
    };

    ScanDiff {
        new_findings,
        fixed_findings,
        unchanged_count,
        risk_delta: RiskDelta {
            before: risk_before,
            after: risk_after,
            delta,
            assessment,
        },
    }
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

/// Weighted risk score for a set of findings.
///
/// Weights: Critical=100, High=10, Medium=3, Low=1.
/// Confidence multiplier: High=100%, Medium=67%, Low=33%.
pub fn risk_score(findings: &[Finding]) -> i64 {
    findings.iter().map(finding_risk).sum()
}

fn finding_risk(f: &Finding) -> i64 {
    let severity_weight: i64 = match f.severity {
        Severity::Critical => 100,
        Severity::High => 10,
        Severity::Medium => 3,
        Severity::Low => 1,
    };
    // Scale by confidence (×100 to avoid floats, then divide at the end)
    let confidence_pct: i64 = match f.confidence {
        Confidence::High => 100,
        Confidence::Medium => 67,
        Confidence::Low => 33,
    };
    (severity_weight * confidence_pct + 50) / 100 // rounded integer division
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn effective_id(f: &Finding) -> String {
    if !f.id.is_empty() {
        f.id.clone()
    } else {
        // Fallback for pre-id findings: composite key
        format!(
            "{}:{}:{}",
            f.file.as_deref().unwrap_or(""),
            f.line,
            f.detector_id
        )
    }
}

fn id_set(findings: &[Finding]) -> HashSet<String> {
    findings.iter().map(effective_id).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Confidence;

    fn finding(id: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            id: id.to_string(),
            detector_id: "test".to_string(),
            severity,
            confidence,
            line: 1,
            vulnerability_type: "Test".to_string(),
            message: String::new(),
            suggestion: String::new(),
            remediation: None,
            owasp_category: None,
            file: Some("foo.sol".to_string()),
        }
    }

    #[test]
    fn diff_finds_new_and_fixed() {
        let before = vec![
            finding("aaa", Severity::High, Confidence::High),
            finding("bbb", Severity::Medium, Confidence::Medium),
        ];
        let after = vec![
            finding("bbb", Severity::Medium, Confidence::Medium), // unchanged
            finding("ccc", Severity::Low, Confidence::Low),       // new
        ];
        let diff = diff_scans(&before, &after);
        assert_eq!(diff.new_findings.len(), 1, "one new finding (ccc)");
        assert_eq!(diff.new_findings[0].id, "ccc");
        assert_eq!(diff.fixed_findings.len(), 1, "one fixed finding (aaa)");
        assert_eq!(diff.fixed_findings[0].id, "aaa");
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn diff_no_changes() {
        let findings = vec![finding("xxx", Severity::High, Confidence::High)];
        let diff = diff_scans(&findings, &findings);
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed_findings.is_empty());
        assert_eq!(diff.risk_delta.delta, 0);
        assert_eq!(diff.risk_delta.assessment, "unchanged");
    }

    #[test]
    fn diff_all_new() {
        let before: Vec<Finding> = vec![];
        let after = vec![finding("zzz", Severity::Critical, Confidence::High)];
        let diff = diff_scans(&before, &after);
        assert_eq!(diff.new_findings.len(), 1);
        assert!(diff.fixed_findings.is_empty());
        assert_eq!(diff.risk_delta.assessment, "regressed");
        assert!(diff.risk_delta.delta > 0);
    }

    #[test]
    fn diff_all_fixed() {
        let before = vec![finding("zzz", Severity::Critical, Confidence::High)];
        let after: Vec<Finding> = vec![];
        let diff = diff_scans(&before, &after);
        assert!(diff.new_findings.is_empty());
        assert_eq!(diff.fixed_findings.len(), 1);
        assert_eq!(diff.risk_delta.assessment, "improved");
        assert!(diff.risk_delta.delta < 0);
    }

    #[test]
    fn risk_score_weights() {
        let critical_high = finding("a", Severity::Critical, Confidence::High);
        let high_high = finding("b", Severity::High, Confidence::High);
        let medium_medium = finding("c", Severity::Medium, Confidence::Medium);
        let low_low = finding("d", Severity::Low, Confidence::Low);

        assert_eq!(finding_risk(&critical_high), 100); // 100 × 100% = 100
        assert_eq!(finding_risk(&high_high), 10);      // 10 × 100% = 10
        assert_eq!(finding_risk(&medium_medium), 2);   // 3 × 67% = 2.01 → 2
        assert_eq!(finding_risk(&low_low), 0);         // 1 × 33% = 0.33 → 0
    }

    #[test]
    fn fallback_id_when_empty() {
        let mut f = finding("", Severity::High, Confidence::High);
        f.file = Some("x.sol".to_string());
        f.line = 42;
        f.detector_id = "reentrancy".to_string();
        assert_eq!(effective_id(&f), "x.sol:42:reentrancy");
    }
}
