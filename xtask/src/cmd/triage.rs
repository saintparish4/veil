//! `cargo xtask triage <corpus>` — operator-facing helper for classifying
//! the findings that `cargo xtask precision` left in `needs-triage`.
//!
//! The tool is deliberately non-interactive: it reads and writes
//! `benchmarks/precision/triage/<corpus>.json` using the same schema the
//! precision runner consumes (an array of `{id, verdict, note}`). This
//! keeps the triage workflow scriptable (pipe `--list-untriaged` into an
//! editor, generate a batch of `--set` flags) and avoids pulling a TUI
//! crate into xtask just to read one line at a time.
//!
//! Typical usage:
//!
//!   # Show the 109 untriaged findings for lido-core as TSV.
//!   cargo xtask triage lido-core --list-untriaged
//!
//!   # Classify two findings in one go.
//!   cargo xtask triage lido-core \
//!       --set d4b8c1a9e3f7a201=real:unchecked external call in Burner._processLoss \
//!       --set 1f2e3d4c5b6a7988=false-positive:OZ v5 nonReentrant guard
//!
//! The tool reads `results/<corpus>/findings.json` (produced by the most
//! recent `cargo xtask precision` run) to sanity-check that every ID
//! passed to `--set` actually exists in the current scan. This catches
//! copy/paste typos before they silently rot in the triage JSON. Use
//! `--force` if you need to overwrite the check (rare — e.g. if you
//! bumped the corpus rev and want to retain old triage notes).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use veil::types::Finding;

use crate::cmd::fetch::load_corpus_file;

#[derive(Debug, Parser)]
pub struct Args {
    /// Corpus name (must appear in `benchmarks/precision/corpus.toml`).
    pub corpus: String,

    /// Classify a finding. Repeatable. Form: `<id>=<verdict>[:<note>]`
    /// where verdict is `real` or `false-positive`. The note (everything
    /// after the first `:`) is copied verbatim into the JSON and may
    /// contain colons itself.
    #[arg(long = "set")]
    pub set: Vec<String>,

    /// Print untriaged findings as TSV:
    /// `<id>\t<detector>\t<severity>\t<file>:<line>\t<message>`.
    #[arg(long)]
    pub list_untriaged: bool,

    /// Print every finding (including already-classified ones) as TSV with
    /// an extra leading verdict column:
    /// `<verdict>\t<id>\t<detector>\t<severity>\t<file>:<line>\t<message>`.
    #[arg(long)]
    pub list_all: bool,

    /// Skip the "id exists in current findings.json" safety check.
    /// Useful when retaining hand-written triage notes across a corpus
    /// rev bump that has renumbered IDs.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TriageEntry {
    pub id: String,
    pub verdict: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Deserialize)]
struct FindingsFileOwned {
    #[allow(dead_code)]
    corpus: String,
    #[allow(dead_code)]
    rev: String,
    #[allow(dead_code)]
    #[serde(default)]
    resolved_sha: Option<String>,
    findings: Vec<Finding>,
}

pub fn run(args: Args) -> Result<()> {
    if args.set.is_empty() && !args.list_untriaged && !args.list_all {
        return Err(anyhow!(
            "nothing to do — pass --list-untriaged, --list-all, or one or more --set entries"
        ));
    }
    if args.list_untriaged && args.list_all {
        return Err(anyhow!(
            "--list-untriaged and --list-all are mutually exclusive"
        ));
    }

    let root = workspace_root()?;
    let corpus_toml = root
        .join("benchmarks")
        .join("precision")
        .join("corpus.toml");
    let corpora = load_corpus_file(&corpus_toml)
        .with_context(|| format!("reading {}", corpus_toml.display()))?;
    if !corpora.iter().any(|c| c.name == args.corpus) {
        return Err(anyhow!(
            "unknown corpus `{}` — valid names: {}",
            args.corpus,
            corpora
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let triage_path = root
        .join("benchmarks")
        .join("precision")
        .join("triage")
        .join(format!("{}.json", args.corpus));
    let findings_path = root
        .join("benchmarks")
        .join("precision")
        .join("results")
        .join(&args.corpus)
        .join("findings.json");

    let findings = load_findings(&findings_path)?;
    let triage = load_triage(&triage_path)?;

    if args.list_untriaged {
        return list_untriaged(&findings, &triage);
    }
    if args.list_all {
        return list_all(&findings, &triage);
    }

    apply_sets(&args.set, &findings, triage, &triage_path, args.force)
}

// ─── Loading ───────────────────────────────────────────────

fn load_findings(path: &Path) -> Result<Vec<Finding>> {
    let text = fs::read_to_string(path).map_err(|e| {
        anyhow!(
            "could not read {} ({e}) — run `cargo xtask precision --allow-untriaged` first",
            path.display()
        )
    })?;
    let parsed: FindingsFileOwned =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(parsed.findings)
}

fn load_triage(path: &Path) -> Result<Vec<TriageEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Ok(Vec::new());
    }
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

// ─── --list-* modes ────────────────────────────────────────

fn list_untriaged(findings: &[Finding], triage: &[TriageEntry]) -> Result<()> {
    let classified: BTreeSet<&str> = triage.iter().map(|t| t.id.as_str()).collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in findings {
        if classified.contains(f.id.as_str()) {
            continue;
        }
        writeln!(
            out,
            "{id}\t{det}\t{sev}\t{file}:{line}\t{msg}",
            id = f.id,
            det = f.detector_id,
            sev = f.severity.as_str(),
            file = f.file.as_deref().unwrap_or("?"),
            line = f.line,
            msg = one_line(&f.message),
        )?;
    }
    Ok(())
}

fn list_all(findings: &[Finding], triage: &[TriageEntry]) -> Result<()> {
    let classified: BTreeMap<&str, &TriageEntry> =
        triage.iter().map(|t| (t.id.as_str(), t)).collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in findings {
        let verdict = classified
            .get(f.id.as_str())
            .map(|t| t.verdict.as_str())
            .unwrap_or("needs-triage");
        writeln!(
            out,
            "{verdict}\t{id}\t{det}\t{sev}\t{file}:{line}\t{msg}",
            verdict = verdict,
            id = f.id,
            det = f.detector_id,
            sev = f.severity.as_str(),
            file = f.file.as_deref().unwrap_or("?"),
            line = f.line,
            msg = one_line(&f.message),
        )?;
    }
    Ok(())
}

fn one_line(s: &str) -> String {
    // Collapse whitespace so TSV stays single-line even if a detector emits
    // a multi-line message.
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─── --set processing ──────────────────────────────────────

struct ParsedSet {
    id: String,
    verdict: String,
    note: String,
}

fn parse_set_entry(raw: &str) -> Result<ParsedSet> {
    let (id, rest) = raw
        .split_once('=')
        .ok_or_else(|| anyhow!("--set `{raw}`: expected `<id>=<verdict>[:<note>]`"))?;
    if !is_valid_id(id) {
        return Err(anyhow!(
            "--set `{raw}`: id `{id}` is not 16 lowercase hex chars"
        ));
    }
    let (verdict, note) = match rest.split_once(':') {
        Some((v, n)) => (v, n),
        None => (rest, ""),
    };
    if verdict != "real" && verdict != "false-positive" {
        return Err(anyhow!(
            "--set `{raw}`: verdict `{verdict}` must be `real` or `false-positive`"
        ));
    }
    Ok(ParsedSet {
        id: id.to_string(),
        verdict: verdict.to_string(),
        note: note.to_string(),
    })
}

fn is_valid_id(s: &str) -> bool {
    s.len() == 16
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn apply_sets(
    raw_entries: &[String],
    findings: &[Finding],
    mut triage: Vec<TriageEntry>,
    triage_path: &Path,
    force: bool,
) -> Result<()> {
    let known_ids: BTreeSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    let mut parsed: Vec<ParsedSet> = Vec::with_capacity(raw_entries.len());
    for raw in raw_entries {
        let p = parse_set_entry(raw)?;
        if !force && !known_ids.contains(p.id.as_str()) {
            return Err(anyhow!(
                "--set `{raw}`: id `{id}` does not appear in the current findings.json. \
                 Pass --force to override (usually means you mistyped, or the corpus rev changed).",
                id = p.id
            ));
        }
        parsed.push(p);
    }

    let mut index: BTreeMap<String, usize> = triage
        .iter()
        .enumerate()
        .map(|(i, t)| (t.id.clone(), i))
        .collect();

    let (mut inserted, mut updated, mut unchanged) = (0usize, 0usize, 0usize);
    for p in parsed {
        match index.get(&p.id).copied() {
            Some(i) => {
                let existing = &triage[i];
                if existing.verdict == p.verdict && existing.note == p.note {
                    unchanged += 1;
                } else {
                    triage[i] = TriageEntry {
                        id: p.id,
                        verdict: p.verdict,
                        note: p.note,
                    };
                    updated += 1;
                }
            }
            None => {
                index.insert(p.id.clone(), triage.len());
                triage.push(TriageEntry {
                    id: p.id,
                    verdict: p.verdict,
                    note: p.note,
                });
                inserted += 1;
            }
        }
    }

    // Canonicalize: sort by id so diffs stay small and deterministic.
    triage.sort_by(|a, b| a.id.cmp(&b.id));

    let mut json = serde_json::to_string_pretty(&triage)?;
    json.push('\n');
    if let Some(parent) = triage_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(triage_path, json).with_context(|| format!("writing {}", triage_path.display()))?;

    let total_classified = triage.len();
    let total_findings = findings.len();
    let still_untriaged = total_findings.saturating_sub(total_classified);
    eprintln!(
        "xtask triage: {inserted} inserted, {updated} updated, {unchanged} unchanged → \
         {total_classified}/{total_findings} classified ({still_untriaged} still untriaged). \
         wrote {}",
        triage_path.display()
    );
    Ok(())
}

// ─── misc ──────────────────────────────────────────────────

fn workspace_root() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow!("xtask CARGO_MANIFEST_DIR has no parent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_id_verdict() {
        let p = parse_set_entry("0123456789abcdef=real").unwrap();
        assert_eq!(p.id, "0123456789abcdef");
        assert_eq!(p.verdict, "real");
        assert_eq!(p.note, "");
    }

    #[test]
    fn parses_id_verdict_note() {
        let p = parse_set_entry("0123456789abcdef=false-positive:OZ v5 guard").unwrap();
        assert_eq!(p.verdict, "false-positive");
        assert_eq!(p.note, "OZ v5 guard");
    }

    #[test]
    fn note_may_contain_colons() {
        let p = parse_set_entry("0123456789abcdef=real:see audit: ChainSec p.14").unwrap();
        assert_eq!(p.note, "see audit: ChainSec p.14");
    }

    #[test]
    fn rejects_bad_verdict() {
        assert!(parse_set_entry("0123456789abcdef=maybe").is_err());
    }

    #[test]
    fn rejects_bad_id_length() {
        assert!(parse_set_entry("deadbeef=real").is_err());
    }

    #[test]
    fn rejects_non_hex_id() {
        assert!(parse_set_entry("0123456789abcdeZ=real").is_err());
    }

    #[test]
    fn validates_hex() {
        assert!(is_valid_id("0123456789abcdef"));
        assert!(!is_valid_id("0123456789ABCDEF")); // uppercase rejected
        assert!(!is_valid_id("0123456789abcde")); // too short
        assert!(!is_valid_id("0123456789abcdef0")); // too long
    }
}
