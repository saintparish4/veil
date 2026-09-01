//! Discovering the files in a project and resolving `import` directives between them.
//!
//! # Why the arena
//!
//! tree-sitter `Node<'a>` borrows its `Tree`. If I stored nodes in the graph, the
//! graph would borrow every tree in the project and nothing could be mutated after
//! construction. So I own the `Tree`s here in a `Vec`, hand out [`SourceUnitId`]
//! indices, and resolve back to nodes on demand. Anything that wants to keep a
//! reference to part of a file keeps `(SourceUnitId, byte_offset)` instead.
//!
//! # What "resolved" means
//!
//! An import that points outside the project root, or at a file that does not
//! exist, is recorded as a [`Diagnostic`] and skipped. It is never a hard error:
//! projects reference dependencies I was not pointed at all the time, and refusing
//! to analyse the other 95% of the code because of it would be useless behaviour.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use tree_sitter::{Node, Parser, Tree};
use veil::ast_utils::node_text;

/// Stable handle to one parsed `.sol` file. Indices into [`Project::units`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceUnitId(pub usize);

/// Something I could not resolve, kept rather than dropped so the gaps in an
/// analysis are visible instead of silently changing the results.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Diagnostic {
    /// File the problem was found in, relative to the project root.
    pub file: String,
    /// Line number, 1-based.
    pub line: usize,
    /// What went wrong, in a form worth showing a user.
    pub message: String,
}

/// One `import` directive, with the literal path as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The quoted path exactly as it appears in the source.
    pub raw_path: String,
    /// The file it resolves to, once resolution has run.
    pub resolved: Option<SourceUnitId>,
    /// Line of the directive, 1-based.
    pub line: usize,
}

/// A parsed Solidity file plus its imports.
pub struct SourceUnit {
    pub id: SourceUnitId,
    /// Path relative to the project root, always with `/` separators so results
    /// are identical on Windows and Unix.
    pub path: String,
    /// Absolute path on disk, used for reading and for remapping lookups.
    pub abs_path: PathBuf,
    pub source: String,
    pub tree: Tree,
    pub imports: Vec<Import>,
    /// True when the file came from a dependency tree (`lib/`, `node_modules/`).
    /// I parse these so imports resolve, but I do not report findings in them.
    pub is_dependency: bool,
    /// True for test and deployment-script files.
    ///
    /// Same treatment as dependencies, and for a stronger reason: a test contract
    /// is *supposed* to have unguarded functions that move funds and change
    /// owners. Reporting on them is not a false positive exactly — the code
    /// really is unprotected — but it is noise no one can act on, and it drowns
    /// the findings that matter.
    pub is_test: bool,
}

impl SourceUnit {
    /// Root node of the parsed tree.
    pub fn root(&self) -> Node<'_> {
        self.tree.root_node()
    }
}

/// Knobs for what gets reported. Resolution itself is unaffected: excluded files
/// are still parsed, because a test helper can declare a base a source file uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Report findings in test and script files too. Off by default.
    pub include_tests: bool,
}

/// A single `from = to` line out of `remappings.txt` or `foundry.toml`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Remapping {
    pub prefix: String,
    pub target: String,
}

/// How the project is laid out on disk. This only changes where I look for
/// remappings and dependencies, not how anything is analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `foundry.toml` present. Dependencies in `lib/`, remappings in
    /// `remappings.txt`.
    Foundry,
    /// `hardhat.config.*` present. Dependencies in `node_modules/`.
    Hardhat,
    /// Neither. Relative imports only.
    Bare,
}

/// Detect the layout by looking for the marker files each toolchain writes.
///
/// Foundry is checked first because a repo can carry both — a Foundry project
/// that also has a Hardhat config for deployment scripts is common, and the
/// Foundry tree is the one that holds the contracts.
pub fn detect_layout(root: &Path) -> Layout {
    if root.join("foundry.toml").is_file() {
        return Layout::Foundry;
    }
    let hardhat = [
        "hardhat.config.js",
        "hardhat.config.ts",
        "hardhat.config.cjs",
    ];
    if hardhat.iter().any(|f| root.join(f).is_file()) {
        return Layout::Hardhat;
    }
    Layout::Bare
}

/// Read remappings from `remappings.txt`, one `prefix=target` per line.
///
/// Sorted longest-prefix-first so lookup can take the first match: given both
/// `@oz/=a/` and `@oz/token/=b/`, an import of `@oz/token/X.sol` must pick `b/`.
pub fn load_remappings(root: &Path) -> Vec<Remapping> {
    let path = root.join("remappings.txt");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out: Vec<Remapping> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(prefix, target)| Remapping {
            prefix: prefix.trim().to_string(),
            target: target.trim().to_string(),
        })
        .filter(|r| !r.prefix.is_empty())
        .collect();
    out.sort_by(|a, b| {
        b.prefix
            .len()
            .cmp(&a.prefix.len())
            .then(a.prefix.cmp(&b.prefix))
    });
    out
}

/// Normalise `.` and `..` without touching the filesystem.
///
/// I deliberately do not use `canonicalize`: it fails on paths that do not exist,
/// and I want a resolution attempt on a missing file to produce a diagnostic
/// naming the path I looked for rather than an opaque IO error. It also resolves
/// symlinks, which would let an import escape the project root.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Render a path relative to the root with `/` separators, so a unit's `path`
/// field is identical across platforms and safe to put in committed output.
fn display_path(root: &Path, abs: &Path) -> String {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Directory names whose contents are dependencies rather than project code.
const DEPENDENCY_DIRS: [&str; 3] = ["lib", "node_modules", "dependencies"];

/// Directory names that hold tests or deployment scripts rather than protocol code.
const TEST_DIRS: [&str; 4] = ["test", "tests", "script", "scripts"];

/// Foundry names test contracts `Foo.t.sol` and scripts `Deploy.s.sol`, and both
/// Foundry and Hardhat put them under a `test/` or `script/` directory. Checking
/// both catches projects that follow only one of the two conventions.
fn is_test_path(root: &Path, abs: &Path) -> bool {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    if rel
        .components()
        .any(|c| TEST_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref()))
    {
        return true;
    }
    let name = abs.file_name().unwrap_or_default().to_string_lossy();
    name.ends_with(".t.sol") || name.ends_with(".s.sol")
}

fn is_dependency_path(root: &Path, abs: &Path) -> bool {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    rel.components()
        .any(|c| DEPENDENCY_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref()))
}

/// Extract the `import` directives from a parsed file.
///
/// The grammar gives an `import_directive` a `string` child holding the path and
/// zero or more `identifier` children for the named or aliased symbols. I only
/// need the path — which file this depends on — so the identifiers are ignored.
/// Symbol-level aliasing matters for name resolution inside expressions, which is
/// not something the contract graph needs.
fn parse_imports(root_node: &Node, source: &str) -> Vec<Import> {
    let mut out = Vec::new();
    for node in veil::ast_utils::find_nodes_of_kind(root_node, "import_directive") {
        let mut cursor = node.walk();
        let path_node = node
            .named_children(&mut cursor)
            .find(|c| c.kind() == "string");
        let Some(path_node) = path_node else { continue };
        let raw = node_text(&path_node, source);
        // The `string` node includes its quotes; both quote styles are legal.
        let trimmed = raw.trim_matches(|c| c == '"' || c == '\'');
        if trimmed.is_empty() {
            continue;
        }
        out.push(Import {
            raw_path: trimmed.to_string(),
            resolved: None,
            line: node.start_position().row + 1,
        });
    }
    out
}

/// Every `.sol` file under `root`, sorted, skipping build output.
///
/// Sorting is what makes [`SourceUnitId`] assignment deterministic, which every
/// downstream ID and every snapshot depends on.
fn discover_sol_files(root: &Path) -> Vec<PathBuf> {
    const SKIP_DIRS: [&str; 5] = ["out", "artifacts", "cache", "target", ".git"];
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.file_type().is_dir() && SKIP_DIRS.contains(&name.as_ref()))
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| p.extension().is_some_and(|x| x == "sol"))
        .collect();
    files.sort();
    files
}

/// The parsed files of a project and the import edges between them.
pub struct SourceUnitGraph {
    pub root: PathBuf,
    pub options: LoadOptions,
    pub layout: Layout,
    pub remappings: Vec<Remapping>,
    pub units: Vec<SourceUnit>,
    pub diagnostics: Vec<Diagnostic>,
    by_abs_path: BTreeMap<PathBuf, SourceUnitId>,
}

impl SourceUnitGraph {
    /// Parse every `.sol` file under `root` and resolve the imports between them.
    ///
    /// Files that fail to parse are still kept as units with whatever tree-sitter
    /// produced — the grammar is error-tolerant, and a file with one bad function
    /// still has usable contract declarations.
    pub fn load(root: &Path) -> std::io::Result<Self> {
        Self::load_with(root, LoadOptions::default())
    }

    /// As [`load`](Self::load), with control over what is reported.
    pub fn load_with(root: &Path, options: LoadOptions) -> std::io::Result<Self> {
        let root = normalize(&std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()));
        let layout = detect_layout(&root);
        let remappings = load_remappings(&root);

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_solidity::LANGUAGE.into())
            .map_err(|e| std::io::Error::other(format!("Solidity grammar: {e}")))?;

        let mut units = Vec::new();
        let mut by_abs_path = BTreeMap::new();
        let mut diagnostics = Vec::new();

        for abs in discover_sol_files(&root) {
            let source = match std::fs::read_to_string(&abs) {
                Ok(s) => s,
                Err(e) => {
                    diagnostics.push(Diagnostic {
                        file: display_path(&root, &abs),
                        line: 0,
                        message: format!("could not read: {e}"),
                    });
                    continue;
                }
            };
            let Some(tree) = parser.parse(&source, None) else {
                diagnostics.push(Diagnostic {
                    file: display_path(&root, &abs),
                    line: 0,
                    message: "parser returned no tree".to_string(),
                });
                continue;
            };
            let id = SourceUnitId(units.len());
            let imports = parse_imports(&tree.root_node(), &source);
            by_abs_path.insert(abs.clone(), id);
            units.push(SourceUnit {
                id,
                path: display_path(&root, &abs),
                is_dependency: is_dependency_path(&root, &abs),
                is_test: is_test_path(&root, &abs),
                abs_path: abs,
                source,
                tree,
                imports,
            });
        }

        let mut graph = Self {
            root,
            options,
            layout,
            remappings,
            units,
            diagnostics,
            by_abs_path,
        };
        graph.resolve_imports();
        Ok(graph)
    }

    /// Point every import at a [`SourceUnitId`] where I can, and record a
    /// diagnostic where I cannot.
    fn resolve_imports(&mut self) {
        // Collected first because resolution borrows `self` immutably while the
        // write-back needs it mutably.
        let mut resolutions: Vec<(usize, usize, Option<SourceUnitId>, Option<Diagnostic>)> =
            Vec::new();

        for (unit_idx, unit) in self.units.iter().enumerate() {
            for (imp_idx, imp) in unit.imports.iter().enumerate() {
                match self.resolve_one(unit, &imp.raw_path) {
                    Some(id) => resolutions.push((unit_idx, imp_idx, Some(id), None)),
                    None => resolutions.push((
                        unit_idx,
                        imp_idx,
                        None,
                        Some(Diagnostic {
                            file: unit.path.clone(),
                            line: imp.line,
                            message: format!("unresolved import `{}`", imp.raw_path),
                        }),
                    )),
                }
            }
        }

        for (unit_idx, imp_idx, resolved, diag) in resolutions {
            self.units[unit_idx].imports[imp_idx].resolved = resolved;
            if let Some(d) = diag {
                self.diagnostics.push(d);
            }
        }
        self.diagnostics.sort();
        self.diagnostics.dedup();
    }

    /// Resolve one import path against the importing file.
    ///
    /// Order matters. A relative path is unambiguous, so it wins outright. Only a
    /// bare path falls through to remappings and then to the dependency roots,
    /// which is the same precedence solc applies.
    fn resolve_one(&self, from: &SourceUnit, raw: &str) -> Option<SourceUnitId> {
        if raw.starts_with("./") || raw.starts_with("../") {
            let base = from.abs_path.parent()?;
            return self.lookup(&normalize(&base.join(raw)));
        }

        for remap in &self.remappings {
            if let Some(rest) = raw.strip_prefix(&remap.prefix) {
                let candidate = normalize(&self.root.join(&remap.target).join(rest));
                if let Some(id) = self.lookup(&candidate) {
                    return Some(id);
                }
            }
        }

        // Unremapped bare path: try the project root, then each dependency root.
        // `@openzeppelin/contracts/...` resolves under `lib/` or `node_modules/`
        // even with no remappings file, which is the common Hardhat case.
        if let Some(id) = self.lookup(&normalize(&self.root.join(raw))) {
            return Some(id);
        }
        for dep in DEPENDENCY_DIRS {
            if let Some(id) = self.lookup(&normalize(&self.root.join(dep).join(raw))) {
                return Some(id);
            }
        }

        // Foundry installs a dependency as `lib/<repo>/src/...` but imports are
        // written `<repo>/src/...`, so the first path segment is already the
        // directory name under `lib/`. Try treating the tail as a path under each
        // installed dependency.
        let tail = raw.split_once('/').map(|(_, t)| t);
        if let Some(tail) = tail {
            for dep in DEPENDENCY_DIRS {
                let dep_root = self.root.join(dep);
                let Ok(entries) = std::fs::read_dir(&dep_root) else {
                    continue;
                };
                let mut dirs: Vec<PathBuf> =
                    entries.filter_map(Result::ok).map(|e| e.path()).collect();
                dirs.sort();
                for d in dirs {
                    if let Some(id) = self.lookup(&normalize(&d.join(tail))) {
                        return Some(id);
                    }
                }
            }
        }

        None
    }

    /// Look up an absolute path, refusing anything that climbed out of the root.
    ///
    /// `../../../etc/passwd` in an import must not make me read outside the tree
    /// I was pointed at.
    fn lookup(&self, abs: &Path) -> Option<SourceUnitId> {
        if !abs.starts_with(&self.root) {
            return None;
        }
        self.by_abs_path.get(abs).copied()
    }

    /// Units I report findings in: project code, excluding vendored dependencies
    /// and (unless asked otherwise) tests and scripts.
    pub fn project_units(&self) -> impl Iterator<Item = &SourceUnit> {
        let include_tests = self.options.include_tests;
        self.units
            .iter()
            .filter(move |u| !u.is_dependency && (include_tests || !u.is_test))
    }

    /// Files reachable from `start` by following imports, including `start`.
    ///
    /// The visited set makes a cyclic import graph terminate. Solidity allows
    /// import cycles and real projects contain them, so this must not recurse
    /// blindly.
    pub fn transitive_imports(&self, start: SourceUnitId) -> BTreeSet<SourceUnitId> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(unit) = self.units.get(id.0) else {
                continue;
            };
            for imp in &unit.imports {
                if let Some(target) = imp.resolved {
                    stack.push(target);
                }
            }
        }
        seen
    }
}
