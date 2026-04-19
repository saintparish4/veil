//! Output formatting: terminal, JSON, and SARIF 2.1.0.
//!
//! `format_*` functions return `String` for library/worker use.
//! `print_*` wrappers (cli-only) call `format_*` + `println!`.

use crate::types::{Finding, Severity, Statistics};
use serde::Serialize;
use std::collections::BTreeMap;

// ============================================================================
// format_* functions — always available, return String
// ============================================================================

pub fn format_json(findings: &[Finding], stats: &Statistics) -> String {
    #[derive(Serialize)]
    struct Output<'a> {
        findings: &'a [Finding],
        statistics: &'a Statistics,
    }

    let output = Output {
        findings,
        statistics: stats,
    };
    serde_json::to_string_pretty(&output).unwrap_or_default()
}

#[cfg(feature = "cli")]
pub fn format_terminal(path: &str, findings: &[Finding], stats: &Statistics) -> String {
    use colored::*;
    let mut out = String::new();

    out.push_str(&format!("\n{}\n", "═".repeat(60).dimmed()));
    out.push_str(&format!(
        "{}\n",
        "Veil Security Scan Results".bold().underline()
    ));
    out.push_str(&format!("{}\n", "═".repeat(60).dimmed()));
    out.push_str(&format!("{} {}\n\n", "Scanning:".bold(), path));

    if findings.is_empty() {
        out.push_str(&format!(
            "{}\n",
            "✓ No vulnerabilities found!".green().bold()
        ));
    } else {
        out.push_str(&format!(
            "{} {} vulnerabilities found:\n\n",
            "⚠".yellow(),
            findings.len()
        ));

        for finding in findings {
            out.push_str(&format!(
                "[{}] {} at line {} (Confidence: {})\n",
                finding.severity.as_colored_str(),
                finding.vulnerability_type.bold(),
                finding.line,
                finding.confidence.as_str().dimmed()
            ));
            out.push_str(&format!("  {} {}\n", "→".cyan(), finding.message));
            out.push_str(&format!(
                "  {} {}\n\n",
                "Fix:".green().bold(),
                finding.suggestion
            ));
        }

        out.push_str(&format!("{}\n", "─".repeat(60).dimmed()));
        out.push_str(&format!("{}\n", "Summary".bold()));
        if stats.critical > 0 {
            out.push_str(&format!("  {} Critical: {}\n", "●".red(), stats.critical));
        }
        if stats.high > 0 {
            out.push_str(&format!("  {} High: {}\n", "●".red(), stats.high));
        }
        if stats.medium > 0 {
            out.push_str(&format!("  {} Medium: {}\n", "●".yellow(), stats.medium));
        }
        if stats.low > 0 {
            out.push_str(&format!("  {} Low: {}\n", "●".blue(), stats.low));
        }
    }
    out.push('\n');
    out
}

// ============================================================================
// print_* wrappers — CLI only
// ============================================================================

#[cfg(feature = "cli")]
pub fn print_results(path: &str, findings: &[Finding], stats: &Statistics) {
    print!("{}", format_terminal(path, findings, stats));
}

#[cfg(feature = "cli")]
pub fn print_json(findings: &[Finding], stats: &Statistics) {
    println!("{}", format_json(findings, stats));
}

// ============================================================================
// SARIF 2.1.0 Output
// ============================================================================

/// SARIF 2.1.0 severity levels.
/// Maps Veil severity to SARIF `level` values.
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Default severity tag for SARIF rule properties (used for GitHub Code Scanning).
fn severity_tag(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

// -- SARIF schema structs (only the subset we need) --------------------------

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    default_configuration: SarifDefaultConfiguration,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifDefaultConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<&'static str>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
}

/// Format findings as SARIF 2.1.0 JSON string.
///
/// Produces a single `run` with one `result` per finding. Rules are
/// deduplicated: each unique vulnerability type becomes one entry in
/// `tool.driver.rules`, and results reference it by `ruleIndex`.
///
/// This output is compatible with GitHub Code Scanning's
/// `github/codeql-action/upload-sarif` action.
pub fn format_sarif(findings: &[Finding]) -> String {
    // Build deduplicated rules list, preserving insertion order via BTreeMap
    // keyed on rule_id so output is deterministic.
    let mut rule_map: BTreeMap<String, (usize, SarifRule)> = BTreeMap::new();

    for f in findings {
        let id = f.detector_id.clone();
        if !rule_map.contains_key(&id) {
            let idx = rule_map.len();
            rule_map.insert(
                id.clone(),
                (
                    idx,
                    SarifRule {
                        id: id.clone(),
                        name: f.vulnerability_type.clone(),
                        short_description: SarifMessage {
                            text: format!("Veil: {} detection", f.vulnerability_type),
                        },
                        default_configuration: SarifDefaultConfiguration {
                            level: sarif_level(&f.severity),
                        },
                        properties: SarifRuleProperties {
                            tags: vec!["security", severity_tag(&f.severity)],
                        },
                    },
                ),
            );
        }
    }

    // Build the ordered rules vec and a quick index lookup.
    let mut rules: Vec<(String, usize, SarifRule)> = rule_map
        .into_iter()
        .map(|(id, (idx, rule))| (id, idx, rule))
        .collect();
    rules.sort_by_key(|(_, idx, _)| *idx);

    let index_of: BTreeMap<String, usize> = rules
        .iter()
        .enumerate()
        .map(|(pos, (id, _, _))| (id.clone(), pos))
        .collect();

    let sarif_rules: Vec<SarifRule> = rules.into_iter().map(|(_, _, r)| r).collect();

    // Build results.
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let id = f.detector_id.clone();
            let rule_index = index_of.get(&id).copied().unwrap_or(0);

            // Combine message + suggestion into the SARIF result message.
            let text = if f.suggestion.is_empty() {
                f.message.clone()
            } else {
                format!("{} Fix: {}", f.message, f.suggestion)
            };

            let uri = f.file.as_deref().unwrap_or("unknown").replace('\\', "/");

            SarifResult {
                rule_id: id,
                rule_index,
                level: sarif_level(&f.severity),
                message: SarifMessage { text },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri },
                        region: SarifRegion { start_line: f.line },
                    },
                }],
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Veil",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/saintparish4/veil",
                    rules: sarif_rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_default()
}

#[cfg(feature = "cli")]
pub fn print_sarif(findings: &[Finding]) {
    println!("{}", format_sarif(findings));
}
