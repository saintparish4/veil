//! `cargo xtask fetch` — routes to the platform-native fetch script,
//! or emits TSV for the PowerShell / bash script to consume.
//!
//! Phase 4 note: `--corpus` now also accepts `recall`. Both families share
//! the same `corpus.toml` schema (see `benchmarks/<family>/corpus.toml`).
//! The emitted TSV gained a leading `family` column so the shell scripts
//! can route clones into `benchmarks/vendor/<family>/<name>/`:
//!
//!     family<TAB>name<TAB>url<TAB>rev

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser)]
pub struct Args {
    /// Which corpus family to hydrate: `precision`, `recall`, or `all`.
    #[arg(long, default_value = "all")]
    pub corpus: String,
    /// Force re-fetch even if a `.veil-resolved-sha` file matches the rev.
    #[arg(long)]
    pub update: bool,
    /// Print `family\tname\turl\trev` per corpus and exit. Used by the
    /// shell scripts.
    #[arg(long)]
    pub emit_tsv: bool,
}

#[derive(Debug, Deserialize)]
struct CorpusFile {
    #[allow(dead_code)]
    schema_version: u32,
    corpus: Vec<CorpusEntry>,
}

#[derive(Debug, Deserialize)]
pub struct CorpusEntry {
    pub name: String,
    pub url: String,
    pub rev: String,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Supported corpus families. Order matters for `--corpus all`.
const FAMILIES: &[&str] = &["precision", "recall"];

pub fn run(args: Args) -> Result<()> {
    let root = workspace_root()?;
    let corpus_name = args.corpus.as_str();

    if !is_known_family(corpus_name) {
        return Err(anyhow!(
            "unknown --corpus `{}` (supported: all, {})",
            corpus_name,
            FAMILIES.join(", ")
        ));
    }

    // TSV mode: enumerate every corpus in the selected family (or all
    // families when `--corpus all`). Missing corpus.toml for a family is
    // silently skipped so the recall corpus.toml is optional until Phase 4
    // is wired end-to-end.
    if args.emit_tsv {
        for fam in selected_families(corpus_name) {
            let toml_path = root.join("benchmarks").join(fam).join("corpus.toml");
            if !toml_path.exists() {
                continue;
            }
            for c in load_corpus_file(&toml_path)? {
                println!("{}\t{}\t{}\t{}", fam, c.name, c.url, c.rev);
            }
        }
        return Ok(());
    }

    let (program, script) = script_for_os(&root);
    if !script.exists() {
        return Err(anyhow!(
            "fetch script not found at {} — did Phase 3 STEP 5/6 land?",
            script.display()
        ));
    }

    println!(
        "xtask fetch: {} {} --corpus {}",
        program,
        script.display(),
        corpus_name
    );
    let mut cmd = Command::new(program);
    cmd.current_dir(&root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match program {
        "pwsh" | "powershell" => {
            cmd.args(["-NoLogo", "-NoProfile", "-File"]);
            cmd.arg(&script);
            cmd.arg("-Corpus").arg(corpus_name);
            if args.update {
                cmd.arg("-Update");
            }
        }
        _ => {
            cmd.arg(&script);
            cmd.arg("--corpus").arg(corpus_name);
            if args.update {
                cmd.arg("--update");
            }
        }
    }
    let status = cmd.status().context("spawning fetch script")?;
    if !status.success() {
        return Err(anyhow!("fetch script exited with {status}"));
    }
    Ok(())
}

fn is_known_family(name: &str) -> bool {
    name == "all" || FAMILIES.contains(&name)
}

fn selected_families(name: &str) -> Vec<&'static str> {
    match name {
        "all" => FAMILIES.to_vec(),
        other => FAMILIES.iter().copied().filter(|f| *f == other).collect(),
    }
}

pub fn load_corpus_file(path: &Path) -> Result<Vec<CorpusEntry>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let parsed: CorpusFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.corpus)
}

fn workspace_root() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("xtask CARGO_MANIFEST_DIR has no parent"))
}

fn script_for_os(root: &Path) -> (&'static str, PathBuf) {
    let scripts = root.join("benchmarks").join("scripts");
    if cfg!(windows) {
        // Prefer pwsh (cross-platform) over legacy powershell.exe.
        let pwsh_ok = Command::new("pwsh").arg("-Version").output().is_ok();
        let program = if pwsh_ok { "pwsh" } else { "powershell" };
        (program, scripts.join("fetch-corpora.ps1"))
    } else {
        ("bash", scripts.join("fetch-corpora.sh"))
    }
}
