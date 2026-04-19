//! Core types: Severity, Confidence, Visibility, Findings, Statistics, Scan outcome, and more.

#[cfg(feature = "cli")]
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    #[cfg(feature = "cli")]
    pub fn as_colored_str(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".green(),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
}

impl Visibility {
    pub fn risk_level(&self) -> u8 {
        match self {
            Visibility::External => 3,
            Visibility::Public => 3,
            Visibility::Internal => 1,
            Visibility::Private => 0,
        }
    }

    pub fn is_externally_callable(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::External)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::External => "external",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub struct Finding {
    pub id: String,
    pub detector_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub line: usize,
    pub vulnerability_type: String,
    pub message: String,
    pub suggestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

impl Finding {
    pub fn compute_id(&mut self) {
        let input = format!(
            "{}:{}:{}",
            self.file.as_deref().unwrap_or(""),
            self.line,
            self.detector_id
        );
        let hash = Sha256::digest(input.as_bytes());
        // Truncate to first 8 bytes (16 hex chars) -- collision-safe for practical use
        self.id = format!(
            "{:016x}",
            u64::from_be_bytes(
                hash[..8]
                    .try_into()
                    .expect("SHA-256 always produces >= 8 bytes")
            )
        );
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub struct Statistics {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub confidence_high: u32,
    pub confidence_medium: u32,
    pub confidence_low: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub struct ScanError {
    pub file: String,
    pub kind: ScanErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub enum ScanErrorKind {
    FileReadError,
    ParseError,
}

#[must_use]
#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "codegen", derive(ts_rs::TS))]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub statistics: Statistics,
    pub errors: Vec<ScanError>,
}
