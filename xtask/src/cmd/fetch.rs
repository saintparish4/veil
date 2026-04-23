//! `cargo xtask fetch` — routes to the platform-native fetch script,
//! or emits TSV for the PowerShell script to consume.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser)]
pub struct Args {
    // Which corpus to hydrate: currently only `precision` (and `all`
    // aliases to that). Kept for Phase 4/5 expansion.
    #[arg(long, default_value = "all")]
    pub corpus: String,
    // Force re-fetch even if a `.veil-resolved-sha` file matches the rev.
    #[arg(long)]
    pub update: bool,
    // Print `name\turl\trev` per corpus and exit. Used by the PS script.
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

pub fn run(args: Args) -> Result<()> {
    let root = workspace_root()?;
    let toml_path = root
        .join("benchmarks")
        .join("precision")
        .join("corpus.toml");

    if args.emit_tsv {
        let entries = load_corpus_file(&toml_path)?;
        for c in entries {
            println!("{}\t{}\t{}", c.name, c.url, c.rev);
        }
        return Ok(());
    }

    if !matches!(args.corpus.as_str(), "all" | "precision") {
        return Err(anyhow!(
            "unknown --corpus `{}` (supported: all, precision)",
            args.corpus
        ));
    }

    let (program, script) = script_for_os(&root);
    if !script.exists() {
        return Err(anyhow!(
            "fetch script not found at {} — did Phase 3 STEP 5/6 land?",
            script.display()
        ));
    }

    println!("xtask fetch: {} {}", program, script.display());
    let mut cmd = Command::new(program);
    cmd.current_dir(&root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match program {
        "pwsh" | "powershell" => {
            cmd.args(["-NoLogo", "-NoProfile", "-File"]);
            cmd.arg(&script);
            if args.update {
                cmd.arg("-Update");
            }
        }
        _ => {
            cmd.arg(&script);
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
