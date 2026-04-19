//! Report engine: HTML and PDF report generation for the CLI.
//!
//! `ReportGenerator` trait defines the interface.
//! `HtmlReport` produces a self-contained HTML string.
//! `PdfReport` delegates to wkhtmltopdf or headless Chrome via subprocess.
//!
//! White-label branding is controlled by `ReportConfig`.
//!

use crate::types::{Finding, Severity, Statistics};

// ==================================================
// Public Types
// ==================================================

/// White-label branding config passed to every report generator
#[derive(Debug, Clone, Default)]
pub struct ReportConfig {
    /// Path to a logo image file. Embedded as base64 in the HTML.
    pub logo_path: Option<String>,
    /// Organization name displayed in the report header
    pub org_name: Option<String>,
}

/// Common interface for all report generators
pub trait ReportGenerator {
    /// Generate the report content
    ///
    /// - `HtmlReport` returns the full HTML string
    /// - `PdfReport` returns the PDF bytes base64-encoded (caller decodes + writes to file)
    fn generate(
        &self,
        path: &str,
        findings: &[Finding],
        stats: &Statistics,
        config: &ReportConfig,
    ) -> Result<String, ReportError>;
}

#[derive(Debug)]
pub enum ReportError {
    /// The external PDF converter (wkhtmltopdf or headless Chrome) was not found on PATH
    ConverterNotFound(String),
    /// The converter process exited with a non-zero status
    ConverterFailed(String),
    /// I/O error (reading the logo file or writing a temp file)  
    IoError(String),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::ConverterNotFound(msg) => {
                write!(f, "PDF converter not found: {}", msg)
            }
            ReportError::ConverterFailed(msg) => write!(f, "PDF converter failed: {}", msg),
            ReportError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

// ============================================================================
// HTML Report
// ============================================================================

pub struct HtmlReport;

impl HtmlReport {
    fn severity_color(s: &Severity) -> &'static str {
        match s {
            Severity::Critical => "#dc2626",
            Severity::High => "#ea580c",
            Severity::Medium => "#d97706",
            Severity::Low => "#2563eb",
        }
    }

    fn severity_badge(s: &Severity) -> String {
        let color = Self::severity_color(s);
        let label = s.as_str();
        format!(
            r#"<span style="background:{color};color:#fff;padding:2px 8px;\
border-radius:4px;font-size:11px;font-weight:700;">{label}</span>"#
        )
    }

    fn logo_html(config: &ReportConfig) -> Result<String, ReportError> {
        let Some(logo_path) = &config.logo_path else {
            return Ok(String::new());
        };
        let bytes = std::fs::read(logo_path)
            .map_err(|e| ReportError::IoError(format!("{logo_path}: {e}")))?;
        let ext = std::path::Path::new(logo_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("png");
        let mime = match ext {
            "svg" => "image/svg+xml",
            "jpg" | "jpeg" => "image/jpeg",
            _ => "image/png",
        };
        let b64 = base64_encode(&bytes);
        Ok(format!(
            r#"<img src="data:{mime};base64,{b64}" style="height:48px;margin-right:16px;" alt="Logo">"#
        ))
    }

    fn owasp_rows(findings: &[Finding]) -> String {
        // OWASP SC Top 10 2026 — prefix codes used for matching against owasp_category field.
        const CATEGORIES: &[(&str, &str)] = &[
            ("SC01", "SC01: Reentrancy"),
            ("SC02", "SC02: Access Control"),
            ("SC03", "SC03: Arithmetic"),
            ("SC04", "SC04: Unchecked Return Values"),
            ("SC05", "SC05: Denial of Service"),
            ("SC06", "SC06: Bad Randomness"),
            ("SC07", "SC07: Front Running"),
            ("SC08", "SC08: Time Manipulation"),
            ("SC09", "SC09: Short Address Attack"),
            ("SC10", "SC10: Unknown Unknowns"),
        ];
        CATEGORIES
            .iter()
            .map(|(code, label)| {
                let count = findings
                    .iter()
                    .filter(|f| {
                        f.owasp_category
                            .as_deref()
                            .is_some_and(|oc: &str| oc.starts_with(code))
                    })
                    .count();
                let (bg, status) = if count > 0 {
                    (
                        "#fee2e2",
                        format!(
                            "<strong style='color:#dc2626;'>{count} finding{s}</strong>",
                            s = if count == 1 { "" } else { "s" }
                        ),
                    )
                } else {
                    (
                        "#f0fdf4",
                        "<span style='color:#16a34a;'>Clean</span>".into(),
                    )
                };
                format!(
                    r#"<tr style="background:{bg}"><td style="padding:6px 12px;">{label}</td>\
<td style="padding:6px 12px;">{status}</td></tr>"#
                )
            })
            .collect()
    }

    fn findings_detail(findings: &[Finding]) -> String {
        if findings.is_empty() {
            return "<p style='color:#16a34a;font-weight:600;'>No vulnerabilities found.</p>"
                .to_string();
        }
        findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let file_str = f.file.as_deref().unwrap_or("unknown");
                let owasp_str = f.owasp_category.as_deref().unwrap_or("—");
                let guidance = match &f.remediation {
                    Some(rem) => format!(
                        "<p><strong>Remediation:</strong> {}</p>",
                        escape_html(rem)
                    ),
                    None => format!(
                        "<p><strong>Suggestion:</strong> {}</p>",
                        escape_html(&f.suggestion)
                    ),
                };
                format!(
                    r#"<div style="border:1px solid #e5e7eb;border-radius:6px;padding:16px;margin-bottom:12px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
    <span style="color:#6b7280;font-size:12px;">#{num}</span>
    {badge}
    <strong>{vuln_type}</strong>
  </div>
  <p style="margin:0 0 4px"><strong>File:</strong> {file} — Line {line}</p>
  <p style="margin:0 0 4px"><strong>Detector:</strong> <code>{det}</code></p>
  <p style="margin:0 0 4px"><strong>OWASP:</strong> {owasp}</p>
  <p style="margin:0 0 4px"><strong>Confidence:</strong> {conf}</p>
  <p style="margin:0 0 8px">{msg}</p>
  {guidance}
</div>"#,
                    num = i + 1,
                    badge = Self::severity_badge(&f.severity),
                    vuln_type = escape_html(&f.vulnerability_type),
                    file = escape_html(file_str),
                    line = f.line,
                    det = escape_html(&f.detector_id),
                    owasp = escape_html(owasp_str),
                    conf = f.confidence.as_str(),
                    msg = escape_html(&f.message),
                    guidance = guidance,
                )
            })
            .collect()
    }
}

impl ReportGenerator for HtmlReport {
    fn generate(
        &self,
        path: &str,
        findings: &[Finding],
        stats: &Statistics,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let org_name = config
            .org_name
            .as_deref()
            .unwrap_or("Veil Security Scanner");
        let logo = Self::logo_html(config)?;
        let owasp_rows = Self::owasp_rows(findings);
        let findings_detail = Self::findings_detail(findings);
        let version = env!("CARGO_PKG_VERSION");
        let total = findings.len();

        // Build generated-at timestamp from std::time (no chrono dep).
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let generated_at = format_unix_ts(ts);

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{org} – Security Report</title>
  <style>
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:32px;background:#f9fafb;color:#111827}}
    .header{{background:#1f2937;color:#f9fafb;padding:24px 32px;border-radius:8px;display:flex;align-items:center;margin-bottom:24px}}
    .header h1{{margin:0;font-size:22px}}.header p{{margin:4px 0 0;opacity:.7;font-size:13px}}
    .section{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:24px;margin-bottom:20px}}
    h2{{margin:0 0 16px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#6b7280}}
    .stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
    .stat{{text-align:center;padding:16px;border-radius:6px;border:1px solid #e5e7eb}}
    .stat .num{{font-size:28px;font-weight:700}}.stat .lbl{{font-size:12px;color:#6b7280;margin-top:2px}}
    table{{width:100%;border-collapse:collapse;font-size:13px}}
    th{{text-align:left;padding:8px 12px;background:#f3f4f6;font-weight:600}}
    code{{background:#f3f4f6;padding:1px 4px;border-radius:3px;font-size:12px}}
    .footer{{text-align:center;color:#9ca3af;font-size:12px;margin-top:24px}}
  </style>
</head>
<body>

<div class="header">
  {logo}
  <div>
    <h1>{org} — Security Report</h1>
    <p>Target: {path_esc} &nbsp;|&nbsp; {generated_at} &nbsp;|&nbsp; Veil v{version}</p>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat"><div class="num" style="color:#dc2626">{critical}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#ea580c">{high}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#d97706">{medium}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#2563eb">{low}</div><div class="lbl">Low</div></div>
  </div>
</div>

<div class="section">
  <h2>OWASP SC Top 10 2026 Coverage</h2>
  <table>
    <tr><th>Category</th><th>Status</th></tr>
    {owasp_rows}
  </table>
</div>

<div class="section">
  <h2>Findings ({total} total)</h2>
  {findings_detail}
</div>

<div class="section">
  <h2>Scanner Coverage</h2>
  <p style="margin:0;font-size:13px;">Veil v{version} — 13 active detectors — OWASP SC Top 10 2026 mapped</p>
</div>

<div class="footer">Generated by <strong>Veil</strong> v{version} &nbsp;·&nbsp; {generated_at}</div>
</body>
</html>"#,
            org = escape_html(org_name),
            logo = logo,
            path_esc = escape_html(path),
            generated_at = generated_at,
            version = version,
            critical = stats.critical,
            high = stats.high,
            medium = stats.medium,
            low = stats.low,
            owasp_rows = owasp_rows,
            total = total,
            findings_detail = findings_detail,
        );

        Ok(html)
    }
}

// ============================================================================
// PDF Report
// ============================================================================

pub struct PdfReport;

enum PdfConverter {
    Wkhtmltopdf,
    Chrome(String),
}

impl PdfReport {
    fn find_converter() -> Option<PdfConverter> {
        if cmd_exists("wkhtmltopdf") {
            return Some(PdfConverter::Wkhtmltopdf);
        }
        for chrome in ["google-chrome", "chromium", "chromium-browser"] {
            if cmd_exists(chrome) {
                return Some(PdfConverter::Chrome(chrome.into()));
            }
        }
        None
    }
}

impl ReportGenerator for PdfReport {
    fn generate(
        &self,
        path: &str,
        findings: &[Finding],
        stats: &Statistics,
        config: &ReportConfig,
    ) -> Result<String, ReportError> {
        let converter = PdfReport::find_converter().ok_or_else(|| {
            ReportError::ConverterNotFound("install wkhtmltopdf or Chromium, then re-run".into())
        })?;

        let html = HtmlReport.generate(path, findings, stats, config)?;

        let tmp_dir = std::env::temp_dir();
        let tmp_html = tmp_dir.join("veil_report_tmp.html");
        let tmp_pdf = tmp_dir.join("veil_report_tmp.pdf");

        std::fs::write(&tmp_html, &html).map_err(|e| ReportError::IoError(e.to_string()))?;

        let status = match &converter {
            PdfConverter::Wkhtmltopdf => std::process::Command::new("wkhtmltopdf")
                .arg("--quiet")
                .arg(&tmp_html)
                .arg(&tmp_pdf)
                .status(),
            PdfConverter::Chrome(bin) => std::process::Command::new(bin)
                .args([
                    "--headless",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--print-to-pdf-no-header",
                    &format!("--print-to-pdf={}", tmp_pdf.display()),
                    &format!("file://{}", tmp_html.display()),
                ])
                .status(),
        };

        match status {
            Ok(s) if s.success() => {
                let bytes =
                    std::fs::read(&tmp_pdf).map_err(|e| ReportError::IoError(e.to_string()))?;
                Ok(base64_encode(&bytes))
            }
            Ok(s) => Err(ReportError::ConverterFailed(format!(
                "exited with status {s}"
            ))),
            Err(e) => Err(ReportError::ConverterFailed(e.to_string())),
        }
    }
}

// ============================================================================
// Private helpers
// ============================================================================

/// Minimal HTML escaping for untrusted strings inserted into templates.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// No-dep base64 encoder (RFC 4648).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Check if a command is available on PATH by probing --version.
fn cmd_exists(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Format a Unix timestamp as a human-readable UTC string without chrono.
/// Output: "2026-03-16 14:30 UTC"  (minute precision, good enough for reports)
fn format_unix_ts(secs: u64) -> String {
    // Days since Unix epoch → calendar date (Gregorian, UTC)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;

    // Civil date calculation (Fliegel & Van Flandern algorithm, public domain)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02} {hour:02}:{minute:02} UTC")
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity, Statistics};

    fn sample_finding() -> Finding {
        Finding {
            id: "abc123".into(),
            detector_id: "reentrancy".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            line: 42,
            vulnerability_type: "Reentrancy".into(),
            message: "State change after external call".into(),
            suggestion: "Apply CEI pattern".into(),
            remediation: Some("Move all state updates before external calls.".into()),
            owasp_category: Some("SC01: Reentrancy".into()),
            file: Some("contracts/Vault.sol".into()),
        }
    }

    #[test]
    fn html_report_contains_required_sections() {
        let findings = vec![sample_finding()];
        let stats = Statistics {
            high: 1,
            ..Default::default()
        };
        let config = ReportConfig::default();
        let html = HtmlReport
            .generate("contracts/", &findings, &stats, &config)
            .expect("generate should succeed");

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("OWASP SC Top 10 2026"));
        assert!(html.contains("Findings"));
        assert!(html.contains("Veil"));
        assert!(html.contains("Reentrancy"));
        assert!(html.contains("Vault.sol"));
        assert!(html.contains("Move all state updates before external calls."));
    }

    #[test]
    fn html_report_custom_org_name() {
        let config = ReportConfig {
            org_name: Some("AcmeCorp Audit".into()),
            ..Default::default()
        };
        let html = HtmlReport
            .generate(".", &[], &Statistics::default(), &config)
            .expect("generate");
        assert!(html.contains("AcmeCorp Audit"));
    }

    #[test]
    fn html_report_no_findings_shows_clean_message() {
        let html = HtmlReport
            .generate(".", &[], &Statistics::default(), &ReportConfig::default())
            .expect("generate");
        assert!(html.contains("No vulnerabilities found"));
    }

    #[test]
    fn html_escape_prevents_xss() {
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }

    #[test]
    fn base64_encode_known_values() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
    }

    #[test]
    fn owasp_rows_marks_category_with_findings() {
        let findings = vec![sample_finding()]; // has SC01
        let rows = HtmlReport::owasp_rows(&findings);
        // SC01 row should show a finding count
        assert!(rows.contains("SC01"));
        assert!(rows.contains("1 finding"));
        // SC02 should be clean
        assert!(rows.contains("SC02"));
        assert!(rows.contains("Clean"));
    }

    #[test]
    fn format_unix_ts_produces_reasonable_output() {
        // Unix epoch = 1970-01-01 00:00 UTC
        assert_eq!(format_unix_ts(0), "1970-01-01 00:00 UTC");
        // 2024-03-16 12:00 UTC ≈ 1710590400
        let s = format_unix_ts(1710590400);
        assert!(s.starts_with("2024-03-16"));
    }
}
