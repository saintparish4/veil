//! `cargo xtask perf` — wraps `cargo bench -p veil --bench scan_bench`,
//! parses Criterion's per-bench artifacts, emits one summary JSON file.
//!
//! Artifacts produced (all under benchmarks/perf/results/):
//!   summary.json       — machine-readable p50/p95/p99 + mean/median/stddev
//!                        per bench, plus aggregate corpus totals.
//!   comparison.md      — only with `--compare slither` AND Docker reachable.
//!
//! Exit codes:
//!   0  ok
//!   1  benches failed, or summary parsing failed on a required file
//!   2  `--compare slither` requested but Docker was not reachable
//!      (soft-fail is opt-in via `--allow-missing-comparator`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Parser)]
pub struct Args {
    // Optional compartor to run against the same corpus (currently slither)
    #[arg(long)]
    pub compare: Option<String>,
    // If `--compare` is passed and the comparator is not runnable, warn
    // instead of exiting non-zero. Defaults off so CI catches regressions.
    #[arg(long)]
    pub allow_missing_comparator: bool,
    // Skip re-running benches and only re-parse exisiting target/criterion/
    // Useful for iterating on the summary format
    #[arg(long)]
    pub no_run: bool,
}

pub fn run(args: Args) -> Result<()> {
    let workspace = workspace_root()?;
    let criterion_dir = workspace.join("target").join("criterion");
    let results_dir = workspace.join("benchmarks").join("perf").join("results");
    fs::create_dir_all(&results_dir)
        .with_context(|| format!("creating {}", results_dir.display()))?;

    if !args.no_run {
        run_criterion(&workspace)?;
    }

    let summary = collect_summary(&criterion_dir)
        .with_context(|| format!("reading {}", criterion_dir.display()))?;
    let out = results_dir.join("summary.json");
    let pretty = serde_json::to_string_pretty(&summary)?;
    fs::write(&out, pretty).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "xtask perf: wrote {} bench entries to {}",
        summary.benches.len(),
        out.display()
    );

    if let Some(tool) = args.compare.as_deref() {
        match tool {
            "slither" => {
                run_slither_comparison(&workspace, &results_dir, args.allow_missing_comparator)?
            }
            other => {
                return Err(anyhow!(
                    "unknown --compare target `{other}` (supported: slither)"
                ))
            }
        }
    }

    Ok(())
}

// ─── Running Criterion ───────────────────────────────────────

fn run_criterion(workspace: &Path) -> Result<()> {
    println!("xtask perf: cargo bench -p veil --bench scan_bench");
    let status = Command::new("cargo")
        .args(["bench", "-p", "veil", "--bench", "scan_bench"])
        .current_dir(workspace)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("invoking cargo bench")?;
    if !status.success() {
        return Err(anyhow!("cargo bench exited with {status}"));
    }
    Ok(())
}

// ─── Parsing Criterion's Per-Bench Artifacts ───────────────────────────────────────

#[derive(Serialize)]
struct Summary {
    /// ISO-8601 UTC timestamp the summary was produced.
    generated_at: String,
    /// Commit SHA of the checkout (best-effort; empty string if `git` fails).
    git_sha: String,
    benches: Vec<BenchEntry>,
    /// Aggregate across the `scan_file/` group: sum of bytes scanned and
    /// median of per-contract medians, so headline README numbers have
    /// exactly one source.
    aggregate: Aggregate,
}

#[derive(Serialize)]
struct BenchEntry {
    /// e.g. `scan_file/modern-liquidity-pool` or `scan_corpus_throughput/full_corpus`.
    id: String,
    group: String,
    function: String,
    /// Criterion's `estimates.json` values (nanoseconds per iteration).
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
    /// Computed from `sample.json` per-iteration timings when available.
    p50_ns: Option<f64>,
    p95_ns: Option<f64>,
    p99_ns: Option<f64>,
    /// Echo of the throughput annotation criterion recorded (bytes or elements).
    throughput: Option<ThroughputInfo>,
}

#[derive(Serialize)]
struct ThroughputInfo {
    kind: &'static str, // "bytes" | "elements"
    value: u64,
}

#[derive(Serialize, Default)]
struct Aggregate {
    scan_file_count: usize,
    scan_file_median_of_medians_ns: f64,
    scan_file_total_bytes: u64,
    corpus_elements: Option<u64>,
    corpus_median_ns: Option<f64>,
}

fn collect_summary(criterion_dir: &Path) -> Result<Summary> {
    if !criterion_dir.exists() {
        return Err(anyhow!(
            "no Criterion output at {} — run without --no-run first",
            criterion_dir.display()
        ));
    }

    let mut benches: Vec<BenchEntry> = Vec::new();
    collect_into(criterion_dir, &mut benches)?;
    benches.sort_by(|a, b| a.id.cmp(&b.id));

    let mut scan_file_medians: Vec<f64> = Vec::new();
    let mut scan_file_bytes: u64 = 0;
    let mut corpus_elements: Option<u64> = None;
    let mut corpus_median: Option<f64> = None;
    for b in &benches {
        if b.group == "scan_file" {
            scan_file_medians.push(b.median_ns);
            if let Some(t) = &b.throughput {
                if t.kind == "bytes" {
                    scan_file_bytes += t.value;
                }
            }
        } else if b.group == "scan_corpus_throughput" {
            corpus_median = Some(b.median_ns);
            corpus_elements = b
                .throughput
                .as_ref()
                .and_then(|t| (t.kind == "elements").then_some(t.value));
        }
    }
    let scan_file_median_of_medians = median(&mut scan_file_medians).unwrap_or(0.0);

    Ok(Summary {
        generated_at: now_iso8601(),
        git_sha: git_sha().unwrap_or_default(),
        aggregate: Aggregate {
            scan_file_count: benches.iter().filter(|b| b.group == "scan_file").count(),
            scan_file_median_of_medians_ns: scan_file_median_of_medians,
            scan_file_total_bytes: scan_file_bytes,
            corpus_elements,
            corpus_median_ns: corpus_median,
        },
        benches,
    })
}

// Walk `target/criterion/` recursively looking for `new/estimates.json`;
// each one corresponds to a single bench id. Criterion stores an extra
// `estimates.json` at the group level which we skip

fn collect_into(dir: &Path, out: &mut Vec<BenchEntry>) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name() != "estimates.json" {
            continue;
        }
        let path = entry.path();
        // Only consume the ones under `<bench>/new/` — the group-level one
        // lives directly under `<group>/` (depth mismatch).
        let parent = path.parent().map(|p| p.file_name()).flatten();
        if parent.map(|n| n != "new").unwrap_or(true) {
            continue;
        }
        match parse_bench_dir(path) {
            Ok(entry) => out.push(entry),
            Err(err) => {
                eprintln!("xtask perf: skipping {}: {err:#}", path.display());
            }
        }
    }
    Ok(())
}

fn parse_bench_dir(estimates_path: &Path) -> Result<BenchEntry> {
    let new_dir = estimates_path
        .parent()
        .ok_or_else(|| anyhow!("estimates.json has no parent"))?;
    let bench_dir = new_dir
        .parent()
        .ok_or_else(|| anyhow!("new/ has no parent"))?;

    let benchmark_json = bench_dir.join("new").join("benchmark.json");
    let sample_json = bench_dir.join("new").join("sample.json");

    let estimates: Value = serde_json::from_str(&fs::read_to_string(estimates_path)?)?;
    let mean_ns = point_estimate(&estimates, "mean")?;
    let median_ns = point_estimate(&estimates, "median")?;
    let std_dev_ns = point_estimate(&estimates, "std_dev").unwrap_or(0.0);

    let (group, function, throughput) = if benchmark_json.exists() {
        let v: Value = serde_json::from_str(&fs::read_to_string(&benchmark_json)?)?;
        let group = v
            .get("group_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let function = v
            .get("function_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let throughput = v.get("throughput").and_then(throughput_from_value);
        (group, function, throughput)
    } else {
        // Best-effort: derive from path like target/criterion/<group>/<function>/new/estimates.json
        let components: Vec<&str> = bench_dir
            .components()
            .rev()
            .take(2)
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        let function = components.first().copied().unwrap_or("").to_string();
        let group = components.get(1).copied().unwrap_or("").to_string();
        (group, function, None)
    };

    let id = if group.is_empty() {
        function.clone()
    } else {
        format!("{group}/{function}")
    };

    let (p50, p95, p99) = if sample_json.exists() {
        percentiles_from_sample(&sample_json).unwrap_or((None, None, None))
    } else {
        (None, None, None)
    };

    Ok(BenchEntry {
        id,
        group,
        function,
        mean_ns,
        median_ns,
        std_dev_ns,
        p50_ns: p50,
        p95_ns: p95,
        p99_ns: p99,
        throughput,
    })
}

fn point_estimate(v: &Value, key: &str) -> Result<f64> {
    v.get(key)
        .and_then(|x| x.get("point_estimate"))
        .and_then(|x| x.as_f64())
        .ok_or_else(|| anyhow!("missing {key}.point_estimate"))
}

fn throughput_from_value(v: &Value) -> Option<ThroughputInfo> {
    // Criterion serialises throughput as `{"Bytes": 12345}` or `{"Elements": 678}`.
    if let Some(n) = v.get("Bytes").and_then(|x| x.as_u64()) {
        return Some(ThroughputInfo {
            kind: "bytes",
            value: n,
        });
    }
    if let Some(n) = v.get("Elements").and_then(|x| x.as_u64()) {
        return Some(ThroughputInfo {
            kind: "elements",
            value: n,
        });
    }
    None
}

// Criterion's sample.json shape:  `{ "iters": [..], "times": [..] }` where
// `times[i]` is total wall-clock ns for `iters[i]` iterations. The per-iteration time is
// is `times[i] / iters[i]`. We sort those and take percentiles, a stable approximation when sample count >= 100 .

fn percentiles_from_sample(path: &Path) -> Result<(Option<f64>, Option<f64>, Option<f64>)> {
    let v: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let iters = v
        .get("iters")
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("sample.json missing iters"))?;
    let times = v
        .get("times")
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("sample.json missing times"))?;
    if iters.len() != times.len() || iters.is_empty() {
        return Ok((None, None, None));
    }
    let mut per_iter: Vec<f64> = iters
        .iter()
        .zip(times.iter())
        .filter_map(|(i, t)| {
            let it = i.as_f64()?;
            let tm = t.as_f64()?;
            if it > 0.0 {
                Some(tm / it)
            } else {
                None
            }
        })
        .collect();
    per_iter.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = per_iter.len();
    Ok((
        percentile(&per_iter, 0.50, n),
        percentile(&per_iter, 0.95, n),
        percentile(&per_iter, 0.99, n),
    ))
}

fn percentile(sorted: &[f64], q: f64, n: usize) -> Option<f64> {
    if n == 0 {
        return None;
    }
    let rank = (q * (n as f64 - 1.0)).round() as usize;
    sorted.get(rank).copied()
}

fn median(xs: &mut [f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = xs.len();
    Some(if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    })
}

// ─── Environment Helpers  ───────────────────────────────────────

fn workspace_root() -> Result<PathBuf> {
    // xtask's CARGO_MANIFEST_DIR is <root>/xtask/ — one parent is the root.
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("xtask CARGO_MANIFEST_DIR has no parent"))
}

fn now_iso8601() -> String {
    // Avoid adding a time crate for one string: shell out to `date` or fall back.
    if let Ok(out) = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                return s.trim().to_string();
            }
        }
    }
    String::new()
}

fn git_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

// ─── Slither Comparator (optional, soft-fail when Docker is missing) ───────────────────────────────────────

fn run_slither_comparison(workspace: &Path, results_dir: &Path, allow_missing: bool) -> Result<()> {
    println!("xtask perf: --compare slither requested");

    // Is Docker on PATH and responsive?
    let docker_ok = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        let msg = "docker daemon not reachable — skipping Slither comparison";
        if allow_missing {
            eprintln!("xtask perf: {msg}");
            return Ok(());
        }
        return Err(anyhow!(msg));
    }

    let corpus = workspace
        .join("benchmarks")
        .join("vendor")
        .join("precision");
    if !corpus.exists() {
        let msg = format!(
            "corpus missing at {} — run `just fetch` first",
            corpus.display()
        );
        if allow_missing {
            eprintln!("xtask perf: {msg}");
            return Ok(());
        }
        return Err(anyhow!(msg));
    }

    // We mount the workspace at /work inside the container and point
    // Slither at the same path structure Veil scans.
    let mount = format!("{}:/work", workspace.to_string_lossy());
    let slither_args = [
        "run",
        "--rm",
        "-v",
        mount.as_str(),
        "-w",
        "/work",
        "trailofbits/slither",
        "/work/benchmarks/vendor/precision",
    ];
    println!("xtask perf: docker {}", slither_args.join(" "));

    let t0 = Instant::now();
    let status = Command::new("docker")
        .args(slither_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("spawning docker run")?;
    let wall = t0.elapsed();

    let mut md = String::new();
    md.push_str("# Perf comparison — Veil vs Slither\n\n");
    md.push_str(&format!("Generated: {}\n\n", now_iso8601()));
    md.push_str(&format!("Corpus: `benchmarks/vendor/precision/`\n\n"));
    md.push_str("| Tool    | Wall time           | Exit code |\n");
    md.push_str("|---------|---------------------|-----------|\n");
    md.push_str(&format!(
        "| Slither | {:>19} | {} |\n",
        format_duration(wall),
        status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into()),
    ));
    md.push_str("\nVeil wall time for the same corpus is recorded in `summary.json` under\n");
    md.push_str("`aggregate.corpus_median_ns` × sample_size. See the nightly bench workflow\n");
    md.push_str("for the multiplier claim cited in the README.\n");

    let out = results_dir.join("comparison.md");
    let mut f = fs::File::create(&out).with_context(|| format!("creating {}", out.display()))?;
    f.write_all(md.as_bytes())?;
    f.flush()?;
    println!("xtask perf: wrote {}", out.display());
    let _ = io::stdout().flush();
    Ok(())
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:03}s", secs, millis)
    }
}
