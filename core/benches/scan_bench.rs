//! Criterion benches for Veil's scanner.
//!
//! Group 1 — `scan_file/<contract>`: measures the full scan pipeline
//!   (read + parse + every detector + suppression filter) on each bundled
//!   Solidity fixture under `core/src/contracts/`, plus three synthetic
//!   small/medium/large fixtures generated in-memory so the bench output
//!   always has a baseline even if the fixtures change.
//!
//! Group 2 — `scan_corpus_throughput`: reports lines-per-second against
//!   the fetched precision corpus under `benchmarks/vendor/precision/`.
//!   Skipped (with a one-line notice) if that directory does not exist
//!   yet — this keeps `cargo bench` green before Phase 3 lands the
//!   fetch scripts.

use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion, Throughput,
};

use veil::detectors::build_registry;
use veil::scan::{new_solidity_parser, scan_file_with};

// ── Locating Inputs ──────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this bench points at core/, so up one level is
    // the workspace root. Fall back to cwd if the env var is missing (SHOULD NOT HAPPEN under `cargo bench`).
    match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir).join(".."),
        None => PathBuf::from("."),
    }
}

fn bundled_contracts() -> Vec<PathBuf> {
    let dir = workspace_root().join("core").join("src").join("contracts");
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "sol"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn corpus_root() -> PathBuf {
    workspace_root()
        .join("benchmarks")
        .join("vendor")
        .join("precision")
}

fn walk_sol_files(root: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p.extension().is_some_and(|e| e == "sol"))
        .collect()
}

fn count_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────
// Synthetic Fixtures (keeps the bench meaningful even if the contracts/dir churns)
// Sizes chosen to straddle common read-world contract sizes
// ────────────────────────────────────────────────────

fn synthetic_contract(lines: usize) -> String {
    let mut out = String::with_capacity(lines * 48);
    out.push_str("// SPDX-License-Identifier: MIT\n");
    out.push_str("pragma solidity ^0.8.20;\n");
    out.push_str("contract Synthetic {\n");
    for i in 0..lines {
        out.push_str(&format!(
            "    function f{i}(uint256 x) public pure returns (uint256) {{ return x + {i}; }}\n"
        ));
    }
    out.push_str("}\n");
    out
}

// ── Group 1: Per-contract latency  ──────────────────────────────────────────────────

fn bench_scan_file(c: &mut Criterion) {
    let registry = build_registry();

    let mut group: BenchmarkGroup<'_, WallTime> = c.benchmark_group("scan_file");
    group.measurement_time(Duration::from_secs(8));

    // 1a. Every bundled fixture.
    for path in bundled_contracts() {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let path_str = path.to_string_lossy().into_owned();
        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        group.throughput(Throughput::Bytes(bytes));
        group.bench_function(name, |b| {
            let mut parser = new_solidity_parser().expect("solidity grammar loads");
            b.iter(|| scan_file_with(black_box(&path_str), &registry, &mut parser));
        });
    }

    // 1b. Synthetic small/medium/large, written to tempfile so scan_file_with
    //     exercises the exact same I/O path as real contracts.
    for (label, n_fns) in [
        ("synth-small", 32_usize),
        ("synth-medium", 256),
        ("synth-large", 1024),
    ] {
        let src = synthetic_contract(n_fns);
        let tmp = std::env::temp_dir().join(format!("veil-bench-{label}.sol"));
        fs::write(&tmp, &src).expect("write synthetic fixture");
        let path_str = tmp.to_string_lossy().into_owned();
        group.throughput(Throughput::Bytes(src.len() as u64));
        group.bench_function(label, |b| {
            let mut parser = new_solidity_parser().expect("solidity grammar loads");
            b.iter(|| scan_file_with(black_box(&path_str), &registry, &mut parser));
        });
    }

    group.finish();
}

// ── Group 2: Corpus Throughput  (lines/s) ──────────────────────────────────────────────────

fn bench_scan_corpus_throughput(c: &mut Criterion) {
    let corpus = corpus_root();
    if !corpus.exists() {
        eprintln!(
            "scan_corpus_throughput: skipping — {} does not exist. Run `just fetch` first.",
            corpus.display()
        );
        return;
    }

    let files = walk_sol_files(&corpus);
    if files.is_empty() {
        eprintln!(
            "scan_corpus_throughput: skipping — no .sol files under {}",
            corpus.display()
        );
        return;
    }

    let total_lines: usize = files.iter().map(|p| count_lines(p)).sum();
    let registry = build_registry();

    let mut group = c.benchmark_group("scan_corpus_throughput");
    group.sample_size(10); // corpus scan is slow; keep wall time reasonable
    group.measurement_time(Duration::from_secs(20));
    group.throughput(Throughput::Elements(total_lines as u64));

    group.bench_function("full_corpus", |b| {
        let mut parser = new_solidity_parser().expect("solidity grammar loads");
        b.iter(|| {
            let mut total_findings: usize = 0;
            for path in &files {
                let path_str = path.to_string_lossy();
                let outcome = scan_file_with(black_box(&path_str), &registry, &mut parser);
                total_findings += outcome.findings.len();
            }
            total_findings
        });
    });

    group.finish();
}

criterion_group!(benches, bench_scan_file, bench_scan_corpus_throughput);
criterion_main!(benches);
