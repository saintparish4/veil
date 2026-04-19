//! Inline suppressions (`// veil-ignore:`) and baseline filtering.

use crate::helpers::normalize_vuln_type;
use crate::types::Finding;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;

/// Parsed inline suppression: (line number that is suppressed, optional vulnerability type).
/// Comment on line N applies to line N and N+1 (comment above code suppresses next line).
/// Format: // veil-ignore: [type] [L<line>]
pub fn parse_veil_ignores(source: &str) -> Vec<(usize, Option<String>)> {
    let mut result = Vec::new();
    for (zero_based, line) in source.lines().enumerate() {
        let line_no = zero_based + 1;
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("//") else {
            continue;
        };
        let rest = rest.trim();
        let Some(rest) = rest.strip_prefix("veil-ignore:") else {
            continue;
        };
        let rest = rest.trim();
        let words: Vec<&str> = rest.split_ascii_whitespace().collect();
        let (type_opt, target_line_opt) = if words.is_empty() {
            (None, None)
        } else {
            let mut target_line_opt: Option<usize> = None;
            let mut type_opt: Option<String> = None;
            for w in &words {
                if w.starts_with('L') && w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_digit()) {
                    target_line_opt = w[1..].parse().ok();
                } else if type_opt.is_none() {
                    type_opt = Some(normalize_vuln_type(w));
                }
            }
            (type_opt, target_line_opt)
        };
        if let Some(target_line) = target_line_opt {
            result.push((target_line, type_opt));
        } else {
            result.push((line_no, type_opt.clone()));
            result.push((line_no + 1, type_opt));
        }
    }
    result
}

/// Returns true if this finding is suppressed by a pre-parsed set of inline ignores.
///
/// Matches the ignore rule against **both** `finding.detector_id` and
/// `finding.vulnerability_type` so that users can write either:
///   `// veil-ignore: tx-origin`  (detector_id)
///   `// veil-ignore: Reentrancy` (vulnerability_type)
fn is_suppressed(ignores: &[(usize, Option<String>)], finding: &Finding) -> bool {
    let type_norm = normalize_vuln_type(&finding.vulnerability_type);
    let id_norm = normalize_vuln_type(&finding.detector_id);
    for (ignored_line, type_opt) in ignores {
        if *ignored_line != finding.line {
            continue;
        }
        match type_opt {
            None => return true,
            Some(t) if t.is_empty() => return true,
            Some(t) => {
                let t_norm = normalize_vuln_type(t);
                if t_norm == type_norm || t_norm == id_norm {
                    return true;
                }
            }
        }
    }
    false
}

/// Filter out findings that are suppressed by `// veil-ignore:` in the source.
pub fn filter_findings_by_inline_ignores(findings: Vec<Finding>, source: &str) -> Vec<Finding> {
    let ignores = parse_veil_ignores(source);
    findings
        .into_iter()
        .filter(|f| !is_suppressed(&ignores, f))
        .collect()
}

// ============================================================================
// Baseline loading
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BaselineFinding {
    #[serde(default)]
    pub file: Option<String>,
    pub line: u64,
    #[serde(rename = "vulnerability_type")]
    pub vulnerability_type: String,
}

#[derive(Debug, Deserialize)]
pub struct BaselineFile {
    pub findings: Vec<BaselineFinding>,
}

/// Load baseline from JSON (same format as scanner output). Returns set of (file, line, type_norm).
pub fn load_baseline(path: &str) -> HashSet<(String, usize, String)> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Could not read baseline file '{}': {}", path, e);
            return HashSet::new();
        }
    };
    let baseline: BaselineFile = match serde_json::from_str(&content) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: Invalid baseline JSON in '{}': {}", path, e);
            return HashSet::new();
        }
    };
    baseline
        .findings
        .into_iter()
        .map(|f| {
            let file = f.file.unwrap_or_default();
            let line = f.line as usize;
            let typ = normalize_vuln_type(&f.vulnerability_type);
            (file, line, typ)
        })
        .collect()
}

/// Filter to findings not in baseline (only "new" findings).
pub fn filter_findings_by_baseline(
    findings: Vec<Finding>,
    baseline_set: &HashSet<(String, usize, String)>,
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| {
            let file = f.file.as_deref().unwrap_or("");
            let key = (
                file.to_string(),
                f.line,
                normalize_vuln_type(&f.vulnerability_type),
            );
            !baseline_set.contains(&key)
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};

    fn make_finding(detector_id: &str, vuln_type: &str, line: usize) -> Finding {
        Finding {
            id: String::new(),
            detector_id: detector_id.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            line,
            vulnerability_type: vuln_type.to_string(),
            message: String::new(),
            suggestion: String::new(),
            remediation: None,
            owasp_category: None,
            file: None,
        }
    }

    // ---------------------------------------------------------------
    // parse_veil_ignores
    // ---------------------------------------------------------------

    #[test]
    fn parse_ignores_bare_suppression() {
        let src = "// veil-ignore:\nuint x = 1;";
        let ignores = parse_veil_ignores(src);
        assert!(ignores.iter().any(|(line, t)| *line == 1 && t.is_none()));
        assert!(ignores.iter().any(|(line, t)| *line == 2 && t.is_none()));
    }

    #[test]
    fn parse_ignores_typed_suppression() {
        let src = "// veil-ignore: reentrancy\nuint x = 1;";
        let ignores = parse_veil_ignores(src);
        assert!(ignores
            .iter()
            .any(|(line, t)| *line == 2 && t.as_deref() == Some("reentrancy")));
    }

    #[test]
    fn parse_ignores_with_target_line() {
        let src = "// veil-ignore: tx-origin L5";
        let ignores = parse_veil_ignores(src);
        assert!(ignores
            .iter()
            .any(|(line, t)| *line == 5 && t.as_deref() == Some("tx origin")));
    }

    #[test]
    fn parse_ignores_skips_non_comments() {
        let src = "uint x = 1;\nfunction foo() {}";
        let ignores = parse_veil_ignores(src);
        assert!(ignores.is_empty());
    }

    // ---------------------------------------------------------------
    // is_suppressed — matching against vulnerability_type
    // ---------------------------------------------------------------

    #[test]
    fn suppressed_by_vulnerability_type() {
        let finding = make_finding("reentrancy", "Reentrancy", 5);
        let ignores = vec![(5, Some("reentrancy".to_string()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    #[test]
    fn not_suppressed_wrong_line() {
        let finding = make_finding("reentrancy", "Reentrancy", 5);
        let ignores = vec![(10, Some("reentrancy".to_string()))];
        assert!(!is_suppressed(&ignores, &finding));
    }

    #[test]
    fn not_suppressed_wrong_type() {
        let finding = make_finding("reentrancy", "Reentrancy", 5);
        let ignores = vec![(5, Some("tx origin".to_string()))];
        assert!(!is_suppressed(&ignores, &finding));
    }

    #[test]
    fn suppressed_bare_ignore_matches_everything() {
        let finding = make_finding("reentrancy", "Reentrancy", 5);
        let ignores = vec![(5, None)];
        assert!(is_suppressed(&ignores, &finding));
    }

    #[test]
    fn suppressed_empty_type_matches_everything() {
        let finding = make_finding("reentrancy", "Reentrancy", 5);
        let ignores = vec![(5, Some(String::new()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    // ---------------------------------------------------------------
    // is_suppressed — matching against detector_id (bug fix)
    // ---------------------------------------------------------------

    #[test]
    fn suppressed_by_detector_id_tx_origin() {
        let finding = make_finding("tx-origin", "tx.origin Authentication", 10);
        let ignores = vec![(10, Some("tx origin".to_string()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    #[test]
    fn suppressed_by_detector_id_unchecked_calls() {
        let finding = make_finding(
            "unchecked-calls",
            "Unchecked External Call Return Values",
            3,
        );
        let ignores = vec![(3, Some("unchecked calls".to_string()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    #[test]
    fn suppressed_by_detector_id_reentrancy() {
        let finding = make_finding("reentrancy", "Reentrancy", 7);
        let ignores = vec![(7, Some("reentrancy".to_string()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    #[test]
    fn suppressed_still_works_via_vulnerability_type() {
        let finding = make_finding("reentrancy", "Reentrancy", 7);
        let ignores = vec![(7, Some("reentrancy".to_string()))];
        assert!(is_suppressed(&ignores, &finding));
    }

    // ---------------------------------------------------------------
    // filter_findings_by_inline_ignores (integration)
    // ---------------------------------------------------------------

    #[test]
    fn filter_suppresses_by_detector_id_in_source() {
        let source = "some code\n// veil-ignore: tx-origin\nrequire(tx.origin == msg.sender);";
        let findings = vec![make_finding("tx-origin", "tx.origin Authentication", 3)];
        let filtered = filter_findings_by_inline_ignores(findings, source);
        assert!(
            filtered.is_empty(),
            "finding should be suppressed by detector_id"
        );
    }

    #[test]
    fn filter_suppresses_by_vulnerability_type_in_source() {
        let source = "some code\n// veil-ignore: Reentrancy\nexternal_call();";
        let findings = vec![make_finding("reentrancy", "Reentrancy", 3)];
        let filtered = filter_findings_by_inline_ignores(findings, source);
        assert!(
            filtered.is_empty(),
            "finding should be suppressed by vulnerability_type"
        );
    }

    #[test]
    fn filter_keeps_unsuppressed_findings() {
        let source = "some code\n// veil-ignore: tx-origin\nrequire(tx.origin == msg.sender);";
        let findings = vec![
            make_finding("tx-origin", "tx.origin Authentication", 3),
            make_finding("reentrancy", "Reentrancy", 3),
        ];
        let filtered = filter_findings_by_inline_ignores(findings, source);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].detector_id, "reentrancy");
    }
}
