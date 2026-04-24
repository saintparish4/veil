//! `cargo xtask recall` -- scan labeled files, compute per-detector recall.
//!
//! Input : benchmarks/recall/labels.yml (YAML list of ground-truth sites)
//! Output: benchmarks/recall/results/{summary.md,summary.json,misses.md,extras.md}
//!
//! Match rule: a finding matches a label iff
//!   (f.file, f.detector_id) == (L.file, L.detector_id) && |f.line - L.line| <= 2

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use veil::detector_trait::DetectorRegistry;
use veil::detectors::build_registry;
use veil::scan::{new_solidity_parser, scan_file_with};
use veil::types::Finding;

use crate::cmd::fetch;

const LINE_TOLERANCE: i64 = 2;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to labels file (default: benchmarks/recall/labels.yml).
    #[arg(long)]
    pub labels: Option<PathBuf>,
    /// Only run labels whose detector_id matches this.
    #[arg(long)]
    pub only_detector: Option<String>,
    /// Skip auto-fetching SmartBugs when vendor/recall is empty.
    #[arg(long)]
    pub no_auto_fetch: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Label {
    file: String,
    detector_id: String,
    line: i64,
    #[serde(default)]
    swc_id: String,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Serialize)]
struct DetectorStat {
    detector_id: String,
    expected: usize,
    caught: usize,
    missed: usize,
    recall_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
struct Summary<'a> {
    total_labels: usize,
    total_caught: usize,
    total_missed: usize,
    recall_pct: Option<f64>,
    per_detector: &'a [DetectorStat],
    extras_count: usize,
}

pub fn run(args: Args) -> Result<()> {
    let workspace = workspace_root()?;
    let bench_root = workspace.join("benchmarks");
    let results_dir = bench_root.join("recall").join("results");
    fs::create_dir_all(&results_dir)?;

    let labels_path = args
        .labels
        .unwrap_or_else(|| bench_root.join("recall").join("labels.yml"));
    let labels_text = fs::read_to_string(&labels_path)
        .with_context(|| format!("reading {}", labels_path.display()))?;
    let mut labels: Vec<Label> = serde_yml::from_str(&labels_text)
        .with_context(|| format!("parsing {}", labels_path.display()))?;
    if let Some(det) = &args.only_detector {
        labels.retain(|l| &l.detector_id == det);
    }
    if labels.is_empty() {
        return Err(anyhow!("no labels found in {}", labels_path.display()));
    }

    // Auto-hydrate vendor/recall if any label points into it and it's empty.
    let vendor_recall = bench_root.join("vendor").join("recall");
    let needs_vendor = labels.iter().any(|l| l.file.starts_with("vendor/recall/"));
    if needs_vendor && !args.no_auto_fetch && vendor_is_empty(&vendor_recall) {
        eprintln!(
            "xtask recall: {} is empty -- running `cargo xtask fetch --corpus recall`",
            vendor_recall.display()
        );
        fetch::run(fetch::Args {
            corpus: "recall".to_string(),
            update: false,
            emit_tsv: false,
        })?;
    }

    let registry = build_registry();
    let mut parser = new_solidity_parser().map_err(|e| anyhow!("solidity grammar: {e}"))?;

    // One scan per unique file so we don't re-parse 10 times for 10 labels.
    let unique_files: Vec<String> = {
        let mut v: Vec<String> = labels.iter().map(|l| l.file.clone()).collect();
        v.sort();
        v.dedup();
        v
    };

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut scanned_files: usize = 0;
    let mut missing_files: Vec<String> = Vec::new();

    for rel in &unique_files {
        let abs = bench_root.join(rel);
        if !abs.exists() {
            missing_files.push(rel.clone());
            continue;
        }
        let abs_str = abs.to_string_lossy();
        let outcome = scan_file_with(&abs_str, &registry, &mut parser);
        scanned_files += 1;

        // Normalise file path back to corpus-relative (forward-slash) so it
        // matches labels.yml exactly.
        for mut f in outcome.findings {
            f.file = Some(rel.replace('\\', "/"));
            f.compute_id();
            all_findings.push(f);
        }
    }

    if !missing_files.is_empty() {
        eprintln!(
            "xtask recall: {} labeled file(s) missing on disk -- treated as misses:",
            missing_files.len()
        );
        for m in &missing_files {
            eprintln!("  - {m}");
        }
    }

    // Match labels -> findings.
    let mut caught_per_det: BTreeMap<String, usize> = BTreeMap::new();
    let mut expected_per_det: BTreeMap<String, usize> = BTreeMap::new();
    let mut misses: Vec<Label> = Vec::new();
    // Track which findings were "used" by at least one label, to compute extras.
    let mut used_finding_idx: Vec<bool> = vec![false; all_findings.len()];

    for lbl in &labels {
        *expected_per_det.entry(lbl.detector_id.clone()).or_insert(0) += 1;

        let mut caught = false;
        for (i, f) in all_findings.iter().enumerate() {
            let same_file = f.file.as_deref() == Some(lbl.file.as_str());
            let same_det = f.detector_id == lbl.detector_id;
            let close = (f.line as i64 - lbl.line).abs() <= LINE_TOLERANCE;
            if same_file && same_det && close {
                used_finding_idx[i] = true;
                caught = true;
            }
        }
        if caught {
            *caught_per_det.entry(lbl.detector_id.clone()).or_insert(0) += 1;
        } else {
            misses.push(lbl.clone());
        }
    }

    // Extras = findings on labeled files whose detector never matched a label.
    // (We only flag extras on labeled files -- findings on unlabeled files are
    // out of scope for recall and are the precision bench's job.)
    let extras: Vec<&Finding> = all_findings
        .iter()
        .enumerate()
        .filter(|(i, _)| !used_finding_idx[*i])
        .map(|(_, f)| f)
        .collect();

    // Per-detector stats.
    let mut per_detector: Vec<DetectorStat> = expected_per_det
        .iter()
        .map(|(det, &exp)| {
            let caught = *caught_per_det.get(det).unwrap_or(&0);
            let recall_pct = if exp > 0 {
                Some(caught as f64 / exp as f64 * 100.0)
            } else {
                None
            };
            DetectorStat {
                detector_id: det.clone(),
                expected: exp,
                caught,
                missed: exp - caught,
                recall_pct,
            }
        })
        .collect();
    per_detector.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));

    let total_labels = labels.len();
    let total_caught = per_detector.iter().map(|d| d.caught).sum::<usize>();
    let total_missed = total_labels - total_caught;
    let recall_pct = if total_labels > 0 {
        Some(total_caught as f64 / total_labels as f64 * 100.0)
    } else {
        None
    };

    // ---- Artifacts ----------------------------------------------------------
    let summary = Summary {
        total_labels,
        total_caught,
        total_missed,
        recall_pct,
        per_detector: &per_detector,
        extras_count: extras.len(),
    };
    fs::write(
        results_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;

    fs::write(
        results_dir.join("summary.md"),
        render_summary_md(&summary, scanned_files, &missing_files),
    )?;
    fs::write(results_dir.join("misses.md"), render_misses_md(&misses))?;
    fs::write(results_dir.join("extras.md"), render_extras_md(&extras))?;

    println!(
        "xtask recall: {caught}/{total} ({pct}) across {dets} detectors -- see {out}",
        caught = total_caught,
        total = total_labels,
        pct = fmt_pct(recall_pct),
        dets = per_detector.len(),
        out = results_dir.display(),
    );
    Ok(())
}

fn render_summary_md(s: &Summary, scanned: usize, missing: &[String]) -> String {
    let mut md = String::new();
    md.push_str("# Recall summary\n\n");
    md.push_str(&format!(
        "- labeled sites: **{}**\n- caught: **{}**\n- missed: **{}**\n- recall: **{}**\n- scanned files: {}\n- extras (finding w/o label on labeled files): {}\n\n",
        s.total_labels, s.total_caught, s.total_missed, fmt_pct(s.recall_pct),
        scanned, s.extras_count,
    ));
    if !missing.is_empty() {
        md.push_str(&format!(
            "> {} labeled file(s) missing on disk -- counted as misses. Fix labels.yml or fetch the corpus.\n\n",
            missing.len()
        ));
    }
    md.push_str("## Per-detector\n\n");
    md.push_str("| Detector | Expected | Caught | Missed | Recall |\n");
    md.push_str("|----------|---------:|-------:|-------:|-------:|\n");
    for d in s.per_detector {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            d.detector_id,
            d.expected,
            d.caught,
            d.missed,
            fmt_pct(d.recall_pct),
        ));
    }
    md.push_str(
        "\nRecall = caught / expected. Match window is ±2 lines. \
         See `misses.md` for labels with no matching finding and `extras.md` \
         for findings on labeled files that no label explains (candidate noise).\n",
    );
    md
}

fn render_misses_md(misses: &[Label]) -> String {
    let mut md = String::from("# Recall -- misses\n\n");
    if misses.is_empty() {
        md.push_str("None. Every labeled site matched a finding within ±2 lines.\n");
        return md;
    }
    md.push_str("| File | Line | Detector | SWC | Notes |\n");
    md.push_str("|------|-----:|----------|-----|-------|\n");
    for lbl in misses {
        md.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            lbl.file,
            lbl.line,
            lbl.detector_id,
            lbl.swc_id,
            lbl.notes.replace('|', "\\|"),
        ));
    }
    md
}

fn render_extras_md(extras: &[&Finding]) -> String {
    let mut md =
        String::from("# Recall -- extras (findings on labeled files without a matching label)\n\n");
    if extras.is_empty() {
        md.push_str("None.\n");
        return md;
    }
    md.push_str(
        "These findings land on labeled files but no label within ±2 lines of them. \
                 They are either legitimate extra catches (add them to labels.yml) or noise \
                 (cross-check with precision triage).\n\n",
    );
    md.push_str("| File | Line | Detector | Severity |\n");
    md.push_str("|------|-----:|----------|----------|\n");
    for f in extras {
        md.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            f.file.as_deref().unwrap_or("?"),
            f.line,
            f.detector_id,
            f.severity.as_str(),
        ));
    }
    md
}

fn fmt_pct(p: Option<f64>) -> String {
    match p {
        Some(v) => format!("{v:.2}%"),
        None => "--".to_string(),
    }
}

fn vendor_is_empty(p: &Path) -> bool {
    match fs::read_dir(p) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true,
    }
}

fn workspace_root() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("xtask CARGO_MANIFEST_DIR has no parent"))
}

// Need to pull DetectorRegistry into scope for call signatures.
#[allow(unused_imports)]
use veil::detector_trait as _veil_det_trait;

// Silence unused-import on some toolchains.
fn _types_are_wired(_r: &DetectorRegistry) {}
