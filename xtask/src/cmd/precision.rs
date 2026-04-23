//! `cargo xtask precision` — scan the precision corpus, join with the
//! hand-triaged verdicts, emit committed artifacts.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use veil::detectors::build_registry;
use veil::scan::{new_solidity_parser, scan_file_with};
use veil::types::Finding;

use crate::cmd::fetch::{self, load_corpus_file, CorpusEntry};

#[derive(Debug, Parser)]
pub struct Args {
    /// Permit findings still in `needs-triage`. CI blocks on them by default.
    #[arg(long)]
    pub allow_untriaged: bool,
    /// Only run for a single corpus name (matches `name` in corpus.toml).
    #[arg(long)]
    pub only: Option<String>,
    /// Optional comparator (reserved; not implemented in Phase 3).
    #[arg(long)]
    pub compare: Option<String>,
    /// Skip the implicit fetch when `benchmarks/vendor/precision` is empty.
    /// Useful in CI where the corpus is pre-hydrated or you want the skip
    /// messages instead of a blocking clone.
    #[arg(long)]
    pub no_auto_fetch: bool,
}

pub fn run(args: Args) -> Result<()> {
    let workspace = workspace_root()?;
    let corpus_toml = workspace
        .join("benchmarks")
        .join("precision")
        .join("corpus.toml");
    let triage_dir = workspace
        .join("benchmarks")
        .join("precision")
        .join("triage");
    let results_dir = workspace
        .join("benchmarks")
        .join("precision")
        .join("results");
    let vendor_root = workspace
        .join("benchmarks")
        .join("vendor")
        .join("precision");
    fs::create_dir_all(&results_dir)?;

    // Auto-hydrate the vendor tree if it's empty. Keeps `just bench-precision`
    // a single shell-agnostic recipe: the "fetch if empty" gate lives in Rust,
    // not in sh/pwsh conditional syntax that diverges across platforms.
    if !args.no_auto_fetch && vendor_is_empty(&vendor_root) {
        eprintln!(
            "xtask precision: {} is empty — running `cargo xtask fetch --corpus precision` first",
            vendor_root.display()
        );
        fetch::run(fetch::Args {
            corpus: "precision".to_string(),
            update: false,
            emit_tsv: false,
        })?;
    }

    let corpora = load_corpus_file(&corpus_toml)?;
    let mut per_corpus: Vec<CorpusResult> = Vec::new();
    let registry = build_registry();

    for c in &corpora {
        if let Some(only) = &args.only {
            if &c.name != only {
                continue;
            }
        }
        let vendor_dir = vendor_root.join(&c.name);
        if !vendor_dir.exists() {
            eprintln!(
                "xtask precision: skipping `{}` — {} missing. Run `just fetch` first.",
                c.name,
                vendor_dir.display()
            );
            continue;
        }

        let r = run_one_corpus(&registry, c, &vendor_dir, &triage_dir, &results_dir)
            .with_context(|| format!("corpus `{}`", c.name))?;
        per_corpus.push(r);
    }

    emit_summaries(&results_dir, &per_corpus)?;

    let untriaged: usize = per_corpus.iter().map(|c| c.needs_triage).sum();
    if untriaged > 0 && !args.allow_untriaged {
        return Err(anyhow!(
            "{untriaged} finding(s) still need triage — add them to \
             benchmarks/precision/triage/<corpus>.json or pass --allow-untriaged"
        ));
    }
    Ok(())
}

// ─── Per-corpus work ───────────────────────────────────────

#[derive(Serialize)]
struct CorpusResult {
    name: String,
    rev: String,
    resolved_sha: Option<String>,
    scanned_files: usize,
    zero_match_globs: Vec<String>,
    total_findings: usize,
    real: usize,
    false_positive: usize,
    needs_triage: usize,
    precision_pct: Option<f64>,
}

#[derive(Serialize)]
struct FindingsFile<'a> {
    corpus: &'a str,
    rev: &'a str,
    resolved_sha: Option<&'a str>,
    findings: &'a [Finding],
}

#[derive(Debug, Deserialize, Clone)]
struct TriageEntry {
    id: String,
    verdict: String, // "real" | "false-positive"
    #[serde(default)]
    note: String,
}

fn run_one_corpus(
    registry: &veil::detector_trait::DetectorRegistry,
    c: &CorpusEntry,
    vendor_dir: &Path,
    triage_dir: &Path,
    results_dir: &Path,
) -> Result<CorpusResult> {
    let resolved_sha = fs::read_to_string(vendor_dir.join(".veil-resolved-sha"))
        .ok()
        .map(|s| s.trim().to_string());

    // Include / exclude globs.
    let includes = build_globset(&c.include)?;
    let excludes = build_globset(&c.exclude)?;
    let include_hits: HashMap<String, usize> =
        c.include.iter().cloned().map(|g| (g, 0usize)).collect();
    let (files, include_hits) = collect_files(vendor_dir, &includes, &excludes, include_hits);

    // Scan every selected file.
    let mut parser = new_solidity_parser().map_err(|e| anyhow!("solidity grammar: {e}"))?;
    let mut findings: Vec<Finding> = Vec::new();
    for path in &files {
        let path_str = path.to_string_lossy();
        let outcome = scan_file_with(&path_str, registry, &mut parser);
        findings.extend(outcome.findings);
    }

    // Rewrite `Finding.file` to a corpus-relative, forward-slash path and
    // recompute `Finding.id` from that normalized form. This is what makes
    // the 16-hex-char IDs in `triage/<corpus>.json` stable across machines
    // — otherwise the hash would embed an absolute path like
    // `/mnt/c/Users/…` on WSL vs `C:\Users\…` on native Windows and the
    // same finding would collide under two different IDs.
    for f in &mut findings {
        if let Some(abs) = f.file.clone() {
            let rel = Path::new(&abs)
                .strip_prefix(vendor_dir)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or(abs);
            f.file = Some(rel);
            f.compute_id();
        }
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));

    // Load triage file and classify.
    let triage_path = triage_dir.join(format!("{}.json", c.name));
    let triage: Vec<TriageEntry> = if triage_path.exists() {
        let text = fs::read_to_string(&triage_path)
            .with_context(|| format!("reading {}", triage_path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", triage_path.display()))?
    } else {
        Vec::new()
    };
    let triage_by_id: BTreeMap<&str, &TriageEntry> =
        triage.iter().map(|t| (t.id.as_str(), t)).collect();

    let mut real = 0usize;
    let mut false_positive = 0usize;
    let mut needs_triage = 0usize;
    for f in &findings {
        match triage_by_id.get(f.id.as_str()) {
            Some(t) if t.verdict == "real" => real += 1,
            Some(t) if t.verdict == "false-positive" => false_positive += 1,
            Some(t) => {
                eprintln!(
                    "xtask precision: `{}` id={} has unknown verdict `{}` — treating as needs-triage",
                    c.name, f.id, t.verdict
                );
                needs_triage += 1;
            }
            None => needs_triage += 1,
        }
    }
    let decided = real + false_positive;
    let precision_pct = if decided > 0 {
        Some((real as f64) / (decided as f64) * 100.0)
    } else {
        None
    };

    // Report zero-match include globs so broken globs surface in CI.
    let zero_match_globs: Vec<String> = include_hits
        .into_iter()
        .filter(|(_, n)| *n == 0)
        .map(|(g, _)| g)
        .collect();
    for g in &zero_match_globs {
        eprintln!(
            "xtask precision: warning — include glob `{g}` matched zero files under {}",
            vendor_dir.display()
        );
    }

    // Write per-corpus artifacts.
    let corpus_out = results_dir.join(&c.name);
    fs::create_dir_all(&corpus_out)?;
    let findings_payload = FindingsFile {
        corpus: &c.name,
        rev: &c.rev,
        resolved_sha: resolved_sha.as_deref(),
        findings: &findings,
    };
    fs::write(
        corpus_out.join("findings.json"),
        serde_json::to_string_pretty(&findings_payload)?,
    )?;
    fs::write(
        corpus_out.join("triage.md"),
        render_triage_md(&c.name, &findings, &triage_by_id),
    )?;

    Ok(CorpusResult {
        name: c.name.clone(),
        rev: c.rev.clone(),
        resolved_sha,
        scanned_files: files.len(),
        zero_match_globs,
        total_findings: findings.len(),
        real,
        false_positive,
        needs_triage,
        precision_pct,
    })
}

fn build_globset(globs: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        b.add(Glob::new(g).with_context(|| format!("invalid glob `{g}`"))?);
    }
    Ok(b.build()?)
}

fn collect_files(
    root: &Path,
    includes: &GlobSet,
    excludes: &GlobSet,
    mut include_hits: HashMap<String, usize>,
) -> (Vec<PathBuf>, HashMap<String, usize>) {
    let mut out: Vec<PathBuf> = Vec::new();
    let includes_empty = includes.is_empty();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().map(|e| e != "sol").unwrap_or(true) {
            continue;
        }
        let rel = match path.strip_prefix(root) {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        if !includes_empty && !includes.is_match(&rel) {
            continue;
        }
        if excludes.is_match(&rel) {
            continue;
        }
        // Count per-glob hits so we can warn on zero-match globs.
        for (glob_str, count) in include_hits.iter_mut() {
            if let Ok(g) = Glob::new(glob_str) {
                if g.compile_matcher().is_match(&rel) {
                    *count += 1;
                }
            }
        }
        out.push(path.to_path_buf());
    }
    (out, include_hits)
}

fn render_triage_md(
    corpus: &str,
    findings: &[Finding],
    triage: &BTreeMap<&str, &TriageEntry>,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Triage — {corpus}\n\n"));
    s.push_str("| Finding ID | Detector | Severity | Line | Verdict | Note |\n");
    s.push_str("|------------|----------|----------|------|---------|------|\n");
    for f in findings {
        let (verdict, note) = match triage.get(f.id.as_str()) {
            Some(t) => (t.verdict.as_str(), t.note.as_str()),
            None => ("needs-triage", ""),
        };
        let file = f.file.as_deref().unwrap_or("?");
        s.push_str(&format!(
            "| `{id}` | {det} | {sev} | {file}:{line} | {verdict} | {note} |\n",
            id = f.id,
            det = f.detector_id,
            sev = f.severity.as_str(),
            file = file,
            line = f.line,
            verdict = verdict,
            note = note.replace('|', "\\|"),
        ));
    }
    s
}

// ─── Aggregate Summaries ───────────────────────────────────────

#[derive(Serialize)]
struct Summary<'a> {
    corpora: &'a [CorpusResult],
    aggregate: AggregateSummary,
}

#[derive(Serialize)]
struct AggregateSummary {
    scanned_files: usize,
    total_findings: usize,
    real: usize,
    false_positive: usize,
    needs_triage: usize,
    precision_pct: Option<f64>,
}

fn emit_summaries(results_dir: &Path, per_corpus: &[CorpusResult]) -> Result<()> {
    let scanned_files: usize = per_corpus.iter().map(|c| c.scanned_files).sum();
    let total_findings: usize = per_corpus.iter().map(|c| c.total_findings).sum();
    let real: usize = per_corpus.iter().map(|c| c.real).sum();
    let false_positive: usize = per_corpus.iter().map(|c| c.false_positive).sum();
    let needs_triage: usize = per_corpus.iter().map(|c| c.needs_triage).sum();
    let decided = real + false_positive;
    let precision_pct = if decided > 0 {
        Some((real as f64) / (decided as f64) * 100.0)
    } else {
        None
    };

    let agg = AggregateSummary {
        scanned_files,
        total_findings,
        real,
        false_positive,
        needs_triage,
        precision_pct,
    };
    let json_payload = Summary {
        corpora: per_corpus,
        aggregate: agg,
    };
    fs::write(
        results_dir.join("summary.json"),
        serde_json::to_string_pretty(&json_payload)?,
    )?;

    let mut md = String::new();
    md.push_str("# Precision summary\n\n");
    md.push_str("| Corpus | Rev | Files | Findings | Real | FP | Needs-triage | Precision |\n");
    md.push_str("|--------|-----|------:|---------:|-----:|---:|-------------:|----------:|\n");
    for c in per_corpus {
        md.push_str(&format!(
            "| {name} | `{rev}` | {files} | {total} | {real} | {fp} | {needs} | {pct} |\n",
            name = c.name,
            rev = c.rev,
            files = c.scanned_files,
            total = c.total_findings,
            real = c.real,
            fp = c.false_positive,
            needs = c.needs_triage,
            pct = fmt_pct(c.precision_pct),
        ));
    }
    md.push_str(&format!(
        "| **aggregate** | — | **{files}** | **{total}** | **{real}** | **{fp}** | **{needs}** | **{pct}** |\n",
        files = json_payload.aggregate.scanned_files,
        total = json_payload.aggregate.total_findings,
        real = json_payload.aggregate.real,
        fp = json_payload.aggregate.false_positive,
        needs = json_payload.aggregate.needs_triage,
        pct = fmt_pct(json_payload.aggregate.precision_pct),
    ));
    md.push_str(
        "\nPrecision = real / (real + false-positive). \
         `needs-triage` findings are blockers: they do not contribute to \
         either numerator or denominator and cause CI to fail unless \
         `--allow-untriaged` is passed.\n",
    );
    fs::write(results_dir.join("summary.md"), md)?;
    Ok(())
}

fn fmt_pct(p: Option<f64>) -> String {
    match p {
        Some(v) => format!("{v:.2}%"),
        None => "—".to_string(),
    }
}

fn vendor_is_empty(vendor_root: &Path) -> bool {
    match fs::read_dir(vendor_root) {
        Ok(mut it) => it.next().is_none(),
        // Missing dir counts as "empty" so the auto-fetch kicks in.
        Err(_) => true,
    }
}

fn workspace_root() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("xtask CARGO_MANIFEST_DIR has no parent"))
}
