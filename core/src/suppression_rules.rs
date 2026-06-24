//! TOML-based suppression and pattern rules for DeFi teams.
//!
//! Rules live in `.veil/rules/*.toml` relative to the project root.
//! Each file may contain multiple `[[rules]]` entries — either suppression rules
//! or pattern rules. Rules are applied after inline `// veil-ignore:` suppression
//! and after baseline filtering.
//!
//! Example rule file (`.veil/rules/defi.toml`):
//! ```toml
//! # Suppression rule — silence a known detector for a specific pattern
//! [[rules]]
//! detector = "reentrancy"
//! if_function_name_contains = "Callback"
//! reason = "Uniswap/Aave callbacks are invoked by verified pool contracts"
//!
//! # Pattern rule — emit a custom finding when a predicate matches
//! [[rules]]
//! id = "custom-timelock"
//! severity = "High"
//! pattern = "function_name_contains('schedule') AND NOT has_modifier('onlyProposer')"
//! message = "Timelock schedule function missing proposer access control"
//! ```
//!
//! Rule type is inferred from the presence of required fields:
//! - Suppression rules require `detector` + `reason`.
//! - Pattern rules require `id` + `pattern` + `message`.
//!
//! All string comparisons are case-insensitive.

use crate::rule_engine::PatternRule;
use crate::types::Finding;
use serde::Deserialize;
use std::{fs, path::Path};

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

/// A single suppression rule loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressionRule {
    /// Detector id to suppress (e.g. `"reentrancy"`, `"flash-loan"`).
    /// Use `"*"` to match all detectors.
    pub detector: String,

    /// Suppress only when the function name contains this substring (case-insensitive).
    #[serde(default)]
    pub if_function_name_contains: Option<String>,

    /// Suppress only when the finding's file path contains this substring (case-insensitive).
    #[serde(default)]
    pub if_file: Option<String>,

    /// Suppress only when the finding's vulnerability_type contains this substring.
    #[serde(default)]
    pub if_vulnerability_type_contains: Option<String>,

    /// Required: human-readable reason for the suppression (audit trail).
    pub reason: String,
}

/// A single TOML `[[rules]]` entry — either a suppression rule or a pattern rule.
///
/// Discriminated by required fields: suppression rules have `detector`+`reason`;
/// pattern rules have `id`+`pattern`+`message`. Serde tries each variant in order.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleEntry {
    Pattern(PatternRule),
    Suppress(SuppressionRule),
}

/// Container that deserializes a `.toml` file with `[[rules]]` sections.
#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<RuleEntry>,
}

/// Both types of rules loaded from a single `.veil/rules/` directory scan.
#[derive(Debug, Default)]
pub struct LoadedRules {
    pub suppression: Vec<SuppressionRule>,
    pub patterns: Vec<PatternRule>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load all `*.toml` files from `rules_dir` and return both suppression and pattern rules.
///
/// Non-existent directories return an empty `LoadedRules` (not an error — project may not
/// have any rules yet).  Malformed TOML files emit a warning to stderr and are
/// skipped so that a single bad file does not break the whole scan.
pub fn load_rules_from_dir(rules_dir: &Path) -> LoadedRules {
    if !rules_dir.exists() {
        return LoadedRules::default();
    }

    let mut loaded = LoadedRules::default();

    let entries = match fs::read_dir(rules_dir) {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "veil: warning: cannot read rules directory '{}': {}",
                rules_dir.display(),
                err
            );
            return LoadedRules::default();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                eprintln!(
                    "veil: warning: cannot read rule file '{}': {}",
                    path.display(),
                    err
                );
                continue;
            }
        };
        match toml::from_str::<RuleFile>(&content) {
            Ok(rf) => {
                for entry in rf.rules {
                    match entry {
                        RuleEntry::Pattern(p) => loaded.patterns.push(p),
                        RuleEntry::Suppress(s) => loaded.suppression.push(s),
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "veil: warning: invalid TOML in '{}': {}",
                    path.display(),
                    err
                );
            }
        }
    }

    loaded
}

/// Convenience: load rules from the default location (`.veil/rules/` relative to `scan_root`).
pub fn load_project_rules(scan_root: &str) -> LoadedRules {
    let dir = Path::new(scan_root).join(".veil").join("rules");
    load_rules_from_dir(&dir)
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/// Return `true` if `finding` matches `rule` and should be suppressed.
pub fn rule_matches(rule: &SuppressionRule, finding: &Finding) -> bool {
    // Detector match
    if rule.detector != "*" && !rule.detector.eq_ignore_ascii_case(&finding.detector_id) {
        return false;
    }

    // File filter
    if let Some(ref file_pat) = rule.if_file {
        let file = finding.file.as_deref().unwrap_or("");
        if !file.to_lowercase().contains(&file_pat.to_lowercase()) {
            return false;
        }
    }

    // Vulnerability type filter
    if let Some(ref vt_pat) = rule.if_vulnerability_type_contains {
        if !finding
            .vulnerability_type
            .to_lowercase()
            .contains(&vt_pat.to_lowercase())
        {
            return false;
        }
    }

    // Function name filter — stored in the finding message as "Function 'name' ..."
    // We extract the name from the message rather than requiring a separate field.
    if let Some(ref fn_pat) = rule.if_function_name_contains {
        // Check both message and vulnerability_type for the pattern
        let haystack = format!("{} {}", finding.message, finding.vulnerability_type);
        if !haystack.to_lowercase().contains(&fn_pat.to_lowercase()) {
            return false;
        }
    }

    true
}

/// Filter out findings suppressed by any of the provided rules.
///
/// Findings that match ANY rule are removed. The rule's `reason` field is
/// available for audit logging (currently logged at debug level).
pub fn filter_findings_by_rules(findings: Vec<Finding>, rules: &[SuppressionRule]) -> Vec<Finding> {
    if rules.is_empty() {
        return findings;
    }
    findings
        .into_iter()
        .filter(|f| {
            let suppressed = rules.iter().any(|r| rule_matches(r, f));
            if suppressed {
                tracing::debug!(
                    detector = %f.detector_id,
                    line = f.line,
                    file = ?f.file,
                    "suppressed by TOML rule"
                );
            }
            !suppressed
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};

    fn finding(detector_id: &str, vuln_type: &str, file: Option<&str>, message: &str) -> Finding {
        Finding {
            id: String::new(),
            detector_id: detector_id.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            line: 1,
            vulnerability_type: vuln_type.to_string(),
            message: message.to_string(),
            suggestion: String::new(),
            remediation: None,
            owasp_category: None,
            file: file.map(|s| s.to_string()),
        }
    }

    fn rule(
        detector: &str,
        fn_contains: Option<&str>,
        file_contains: Option<&str>,
        vt_contains: Option<&str>,
    ) -> SuppressionRule {
        SuppressionRule {
            detector: detector.to_string(),
            if_function_name_contains: fn_contains.map(|s| s.to_string()),
            if_file: file_contains.map(|s| s.to_string()),
            if_vulnerability_type_contains: vt_contains.map(|s| s.to_string()),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn rule_matches_by_detector_id() {
        let r = rule("reentrancy", None, None, None);
        let f = finding("reentrancy", "Reentrancy", None, "");
        assert!(rule_matches(&r, &f));
    }

    #[test]
    fn rule_no_match_different_detector() {
        let r = rule("flash-loan", None, None, None);
        let f = finding("reentrancy", "Reentrancy", None, "");
        assert!(!rule_matches(&r, &f));
    }

    #[test]
    fn wildcard_detector_matches_all() {
        let r = rule("*", None, None, None);
        let f1 = finding("reentrancy", "Reentrancy", None, "");
        let f2 = finding("flash-loan", "Flash Loan", None, "");
        assert!(rule_matches(&r, &f1));
        assert!(rule_matches(&r, &f2));
    }

    #[test]
    fn file_filter_applied() {
        let r = rule("reentrancy", None, Some("receivers/"), None);
        let in_receivers = finding("reentrancy", "Reentrancy", Some("src/receivers/Foo.sol"), "");
        let elsewhere = finding("reentrancy", "Reentrancy", Some("src/core/Vault.sol"), "");
        assert!(rule_matches(&r, &in_receivers));
        assert!(!rule_matches(&r, &elsewhere));
    }

    #[test]
    fn function_name_filter_from_message() {
        let r = rule("reentrancy", Some("Callback"), None, None);
        let cb = finding("reentrancy", "Reentrancy", None, "External call at line 10, state change at line 12 -- in uniswapV2Callback");
        let normal = finding("reentrancy", "Reentrancy", None, "External call at line 10, state change at line 12");
        assert!(rule_matches(&r, &cb));
        assert!(!rule_matches(&r, &normal));
    }

    #[test]
    fn filter_removes_matching_suppresses_rest() {
        let rules = vec![rule("flash-loan", None, None, None)];
        let findings = vec![
            finding("flash-loan", "Flash Loan", None, ""),
            finding("reentrancy", "Reentrancy", None, ""),
        ];
        let filtered = filter_findings_by_rules(findings, &rules);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].detector_id, "reentrancy");
    }

    #[test]
    fn empty_rules_passes_all_through() {
        let findings = vec![finding("reentrancy", "Reentrancy", None, "")];
        let filtered = filter_findings_by_rules(findings.clone(), &[]);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn toml_round_trip() {
        let toml_src = r#"
[[rules]]
detector = "reentrancy"
if_function_name_contains = "Callback"
reason = "Pool callbacks are trusted"

[[rules]]
detector = "*"
if_file = "test/"
reason = "Skip test files"
"#;
        let rf: RuleFile = toml::from_str(toml_src).expect("parse");
        assert_eq!(rf.rules.len(), 2);
        let r0 = match &rf.rules[0] {
            RuleEntry::Suppress(r) => r,
            _ => panic!("expected suppression rule"),
        };
        assert_eq!(r0.detector, "reentrancy");
        assert_eq!(r0.if_function_name_contains.as_deref(), Some("Callback"));
        let r1 = match &rf.rules[1] {
            RuleEntry::Suppress(r) => r,
            _ => panic!("expected suppression rule"),
        };
        assert_eq!(r1.detector, "*");
        assert_eq!(r1.if_file.as_deref(), Some("test/"));
    }

    #[test]
    fn toml_pattern_rule_round_trip() {
        let toml_src = r#"
[[rules]]
id = "custom-no-guard"
severity = "High"
pattern = "function_name_contains('schedule') AND NOT has_modifier('onlyProposer')"
message = "Missing access control"
"#;
        let rf: RuleFile = toml::from_str(toml_src).expect("parse");
        assert_eq!(rf.rules.len(), 1);
        let pr = match &rf.rules[0] {
            RuleEntry::Pattern(p) => p,
            _ => panic!("expected pattern rule"),
        };
        assert_eq!(pr.id, "custom-no-guard");
        assert_eq!(pr.severity, "High");
        assert!(pr.pattern.contains("schedule"));
    }
}
