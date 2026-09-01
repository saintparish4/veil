//! `veil analyze <dir>` — project mode.
//!
//! `veil scan` looks at one file at a time and is deliberately fast. It is also
//! blind to anything declared elsewhere, which for Solidity is most of what
//! decides whether code is safe: `onlyOwner` lives in an imported base, the
//! interface behind `IVault(addr)` is in a third file.
//!
//! `analyze` resolves the whole tree first, then runs the same detectors with
//! those facts attached. Same detectors, same output formats, better answers.
//!
//! `--compare` runs both modes over the same files and reports what changed.
//! That number is the point of the command: it is a direct measurement of how
//! many findings were artefacts of only being able to see one file.

use colored::*;
use std::path::Path;

use veil::diff::diff_scans;
use veil::scan::{exit_code_for_stats, scan_parsed_with_project};
use veil::suppression_rules::LoadedRules;
use veil::types::Finding;
use veil::{calculate_statistics, print_json, print_results, print_sarif, ProjectFacts};
use veil_project::{LoadOptions, Project};

/// Everything `analyze` accepts, mirroring `scan` where the flags overlap.
pub struct Args {
    pub path: String,
    pub format: String,
    pub compare: bool,
    pub show_diagnostics: bool,
    pub no_rules: bool,
    pub baseline: Option<String>,
    pub include_tests: bool,
    pub explain_access_control: bool,
}

/// Counts describing what resolution actually managed to do.
///
/// I print these on every run because an analysis over a project where half the
/// imports failed is worth much less than one where they all resolved, and the
/// user has no way to know which they got otherwise.
struct Resolution {
    analysed_files: usize,
    dependency_files: usize,
    contracts: usize,
    interfaces: usize,
    libraries: usize,
    imports_total: usize,
    imports_unresolved: usize,
}

fn summarize(project: &Project) -> Resolution {
    use veil_project::ContractKind;
    let analysed_files = project.sources.project_units().count();
    let excluded = project.sources.units.len() - analysed_files;
    let imports_total: usize = project.sources.units.iter().map(|u| u.imports.len()).sum();
    let imports_unresolved: usize = project
        .sources
        .units
        .iter()
        .flat_map(|u| u.imports.iter())
        .filter(|i| i.resolved.is_none())
        .count();

    Resolution {
        analysed_files,
        dependency_files: excluded,
        contracts: project
            .contracts
            .contracts
            .iter()
            .filter(|c| c.kind == ContractKind::Contract)
            .count(),
        interfaces: project
            .contracts
            .contracts
            .iter()
            .filter(|c| c.kind == ContractKind::Interface)
            .count(),
        libraries: project
            .contracts
            .contracts
            .iter()
            .filter(|c| c.kind == ContractKind::Library)
            .count(),
        imports_total,
        imports_unresolved,
    }
}

fn print_resolution(path: &str, r: &Resolution) {
    println!();
    println!("{}   {}", "PROJECT".bold(), path.dimmed());
    println!();
    println!(
        "  {:<14} {} analysed{}",
        "Files",
        r.analysed_files,
        if r.dependency_files > 0 {
            format!(
                ", {} dependency/test files parsed for resolution only",
                r.dependency_files
            )
        } else {
            String::new()
        }
    );
    println!(
        "  {:<14} {} contracts, {} interfaces, {} libraries",
        "Declarations", r.contracts, r.interfaces, r.libraries
    );
    let unresolved = if r.imports_unresolved == 0 {
        "0 unresolved".green().to_string()
    } else {
        format!("{} unresolved", r.imports_unresolved)
            .yellow()
            .to_string()
    };
    println!(
        "  {:<14} {} resolved, {}",
        "Imports",
        r.imports_total - r.imports_unresolved,
        unresolved
    );
    println!();
}

/// Analyse every project file, optionally with cross-file facts attached.
fn run_detectors(project: &Project, rules: &LoadedRules, with_facts: bool) -> Vec<Finding> {
    let registry = veil::detectors::build_registry();
    let facts: Option<&dyn ProjectFacts> = if with_facts { Some(project) } else { None };

    let mut findings = Vec::new();
    for unit in project.sources.project_units() {
        findings.extend(scan_parsed_with_project(
            &unit.path,
            &unit.source,
            &unit.tree,
            &registry,
            &rules.patterns,
            facts,
        ));
    }
    findings
}

/// Render the file-mode versus project-mode difference.
///
/// `diff_scans(before, after)` already answers this: findings "fixed" between
/// file mode and project mode are the ones resolution suppressed, and "new" ones
/// are what it revealed. Reusing it keeps one definition of finding identity.
fn print_comparison(file_mode: &[Finding], project_mode: &[Finding], as_json: bool) {
    let diff = diff_scans(file_mode, project_mode);
    let suppressed = &diff.fixed_findings;
    let revealed = &diff.new_findings;

    if as_json {
        let payload = serde_json::json!({
            "file_mode_findings": file_mode.len(),
            "project_mode_findings": project_mode.len(),
            "suppressed_by_resolution": suppressed.len(),
            "revealed_by_resolution": revealed.len(),
            "suppressed": suppressed,
            "revealed": revealed,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return;
    }

    println!("{}", "CROSS-FILE RESOLUTION".bold());
    println!();
    println!("  {:<14} {} findings", "file mode", file_mode.len());
    println!("  {:<14} {} findings", "project mode", project_mode.len());
    println!();
    println!(
        "  {:>4}  {}",
        format!("-{}", suppressed.len()).green().bold(),
        "suppressed — resolved to a real guard the per-file view could not see".dimmed()
    );
    println!(
        "  {:>4}  {}",
        format!("+{}", revealed.len()).red().bold(),
        "revealed — a guard that does not actually gate on the caller".dimmed()
    );

    for (label, set) in [("Suppressed", suppressed), ("Revealed", revealed)] {
        if set.is_empty() {
            continue;
        }
        println!();
        println!("  {}:", label.bold());
        for f in set.iter().take(20) {
            println!(
                "    {}:{}  {}  {}",
                f.file.as_deref().unwrap_or("?").dimmed(),
                f.line,
                f.detector_id,
                f.vulnerability_type
            );
        }
        if set.len() > 20 {
            println!("    {} more", set.len() - 20);
        }
    }
    println!();
}

/// Print every modifier in the project and whether it gates on the caller.
///
/// This is the audit I run whenever the resolution logic changes, and the one I
/// would run before trusting Veil on an unfamiliar codebase. A modifier listed
/// under "does not gate" that clearly should is a false-positive generator; one
/// listed under "gates" that clearly should not is a missed bug. Both are
/// findable by eye in a few seconds, which is the point — the judgement stays
/// cheap to check.
fn explain_access_control(project: &Project) {
    use std::collections::BTreeMap;
    let mut gating: BTreeMap<String, usize> = BTreeMap::new();
    let mut not_gating: BTreeMap<String, usize> = BTreeMap::new();
    let mut unresolved: BTreeMap<String, usize> = BTreeMap::new();

    for contract in &project.contracts.contracts {
        let Some(unit) = project.sources.units.get(contract.unit.0) else {
            continue;
        };
        if unit.is_dependency || (unit.is_test && !project.sources.options.include_tests) {
            continue;
        }
        for function in &contract.functions {
            for name in &function.modifiers {
                let bucket = match project.resolve_modifier(&contract.name, name) {
                    Some(f) if f.gates_on_caller => &mut gating,
                    Some(_) => &mut not_gating,
                    None => &mut unresolved,
                };
                *bucket.entry(name.clone()).or_default() += 1;
            }
        }
    }

    println!();
    println!("{}", "ACCESS CONTROL RESOLUTION".bold());
    for (label, set) in [
        ("gates on the caller", &gating),
        ("does NOT gate on the caller", &not_gating),
        ("could not resolve", &unresolved),
    ] {
        println!();
        println!("  {} ({})", label.bold(), set.values().sum::<usize>());
        let mut rows: Vec<_> = set.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (name, count) in rows {
            println!("    {count:>4}  {name}");
        }
        if set.is_empty() {
            println!("    {}", "none".dimmed());
        }
    }
    println!();
}

pub fn run(args: Args) -> i32 {
    if !Path::new(&args.path).is_dir() {
        eprintln!(
            "{} `analyze` takes a project directory. Use `veil scan` for a single file.",
            "Error:".red().bold()
        );
        return 2;
    }

    let options = LoadOptions {
        include_tests: args.include_tests,
    };
    let project = match Project::load_with(&args.path, options) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} could not load project: {e}", "Error:".red().bold());
            return 2;
        }
    };

    let rules = if args.no_rules {
        LoadedRules::default()
    } else {
        veil::suppression_rules::load_project_rules(&args.path)
    };

    if args.explain_access_control {
        explain_access_control(&project);
    }

    let resolution = summarize(&project);
    let diagnostics = project.diagnostics();

    let mut findings = run_detectors(&project, &rules, true);

    if let Some(ref baseline_path) = args.baseline {
        let baseline_set = veil::load_baseline(baseline_path);
        findings = veil::filter_findings_by_baseline(findings, &baseline_set);
    }
    if !rules.suppression.is_empty() {
        findings = veil::suppression_rules::filter_findings_by_rules(findings, &rules.suppression);
    }

    if args.compare {
        let file_mode = run_detectors(&project, &rules, false);
        print_comparison(&file_mode, &findings, args.format == "json");
        if args.format == "json" {
            return 0;
        }
    }

    let stats = calculate_statistics(&findings);

    match args.format.as_str() {
        "json" => print_json(&findings, &stats),
        "sarif" => print_sarif(&findings),
        _ => {
            print_resolution(&args.path, &resolution);
            print_results(&args.path, &findings, &stats);
        }
    }

    // Diagnostics go to stderr so they never corrupt piped JSON or SARIF.
    if !diagnostics.is_empty() {
        if args.show_diagnostics {
            eprintln!();
            eprintln!("{}", "RESOLUTION DIAGNOSTICS".bold());
            for d in &diagnostics {
                eprintln!("  {}:{}  {}", d.file, d.line, d.message);
            }
        } else if args.format != "json" && args.format != "sarif" {
            eprintln!(
                "{} {} resolution diagnostic(s); re-run with --show-diagnostics",
                "note:".yellow().bold(),
                diagnostics.len()
            );
        }
    }

    exit_code_for_stats(&stats)
}
