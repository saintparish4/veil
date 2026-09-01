//! Import resolution: the paths I can follow, and the ones I must refuse.

mod common;

use common::project;
use veil_project::{Layout, Project};

#[test]
fn relative_import_resolves() {
    let (_dir, p) = project(&[
        (
            "src/Vault.sol",
            "import \"./Base.sol\";\ncontract Vault is Base {}",
        ),
        ("src/Base.sol", "contract Base {}"),
    ]);

    let vault = p
        .sources
        .units
        .iter()
        .find(|u| u.path.ends_with("Vault.sol"))
        .expect("Vault unit");
    assert_eq!(vault.imports.len(), 1);
    assert!(
        vault.imports[0].resolved.is_some(),
        "relative import left unresolved"
    );
    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
}

#[test]
fn parent_relative_import_resolves() {
    let (_dir, p) = project(&[
        (
            "src/vault/Vault.sol",
            "import \"../token/Token.sol\";\ncontract Vault {}",
        ),
        ("src/token/Token.sol", "contract Token {}"),
    ]);
    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
}

#[test]
fn remapped_import_resolves() {
    let (_dir, p) = project(&[
        ("foundry.toml", "[profile.default]\nsrc = 'src'\n"),
        (
            "remappings.txt",
            "@openzeppelin/=lib/openzeppelin-contracts/contracts/\n",
        ),
        (
            "src/Vault.sol",
            "import \"@openzeppelin/access/Ownable.sol\";\ncontract Vault is Ownable {}",
        ),
        (
            "lib/openzeppelin-contracts/contracts/access/Ownable.sol",
            "contract Ownable {}",
        ),
    ]);

    assert_eq!(p.sources.layout, Layout::Foundry);
    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
    assert_eq!(p.contracts.contracts.len(), 2);
}

#[test]
fn longest_remapping_prefix_wins() {
    // Both prefixes match `@oz/token/X.sol`. Taking the shorter one would resolve
    // to the wrong file, so ordering by prefix length is load-bearing.
    let (_dir, p) = project(&[
        ("foundry.toml", ""),
        ("remappings.txt", "@oz/=a/\n@oz/token/=b/\n"),
        (
            "src/Use.sol",
            "import \"@oz/token/X.sol\";\ncontract Use {}",
        ),
        ("a/token/X.sol", "contract WrongX {}"),
        ("b/X.sol", "contract RightX {}"),
    ]);

    let use_unit = p
        .sources
        .units
        .iter()
        .find(|u| u.path.ends_with("Use.sol"))
        .expect("Use unit");
    let target = use_unit.imports[0].resolved.expect("resolved");
    assert!(p.sources.units[target.0].path.starts_with("b/"));
}

#[test]
fn bare_import_falls_back_to_dependency_dirs() {
    // No remappings file at all, which is the common Hardhat case.
    let (_dir, p) = project(&[
        ("hardhat.config.js", "module.exports = {};"),
        (
            "contracts/Vault.sol",
            "import \"@openzeppelin/contracts/access/Ownable.sol\";\ncontract Vault is Ownable {}",
        ),
        (
            "node_modules/@openzeppelin/contracts/access/Ownable.sol",
            "contract Ownable {}",
        ),
    ]);

    assert_eq!(p.sources.layout, Layout::Hardhat);
    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
}

#[test]
fn missing_import_is_a_diagnostic_not_a_panic() {
    let (_dir, p) = project(&[("src/Vault.sol", "import \"./Nope.sol\";\ncontract Vault {}")]);

    let diags = p.diagnostics();
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("unresolved import")),
        "{diags:?}"
    );
    // The rest of the file is still analysed.
    assert_eq!(p.contracts.contracts.len(), 1);
}

#[test]
fn cyclic_imports_terminate() {
    // Solidity permits import cycles and real projects contain them. A naive
    // traversal hangs here; the test exists to make sure that never ships.
    let (_dir, p) = project(&[
        ("A.sol", "import \"./B.sol\";\ncontract A is B {}"),
        ("B.sol", "import \"./C.sol\";\ncontract B {}"),
        ("C.sol", "import \"./A.sol\";\ncontract C {}"),
    ]);

    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
    for unit in &p.sources.units {
        // Reaches all three regardless of entry point, without looping.
        assert_eq!(p.sources.transitive_imports(unit.id).len(), 3);
    }
}

#[test]
fn import_cannot_escape_the_project_root() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("project");
    // A file that exists on disk but sits outside the tree I was pointed at.
    common::write_all(dir.path(), &[("outside/Secret.sol", "contract Secret {}")]);
    common::write_all(
        &root,
        &[(
            "src/Vault.sol",
            "import \"../../outside/Secret.sol\";\ncontract Vault {}",
        )],
    );

    let p = Project::load(&root).expect("load");
    assert!(
        p.contracts.unique_by_name("Secret").is_none(),
        "resolution escaped the project root"
    );
    assert!(p
        .diagnostics()
        .iter()
        .any(|d| d.message.contains("unresolved import")));
}

#[test]
fn dependency_files_are_parsed_but_marked() {
    // I need `lib/` parsed so `is Ownable` resolves, but findings should not be
    // reported against vendored code.
    let (_dir, p) = project(&[
        ("foundry.toml", ""),
        ("remappings.txt", "oz/=lib/oz/\n"),
        (
            "src/Vault.sol",
            "import \"oz/Ownable.sol\";\ncontract Vault is Ownable {}",
        ),
        ("lib/oz/Ownable.sol", "contract Ownable {}"),
    ]);

    let project_paths: Vec<&str> = p.sources.project_units().map(|u| u.path.as_str()).collect();
    assert_eq!(project_paths, vec!["src/Vault.sol"]);
    assert_eq!(p.sources.units.len(), 2, "lib/ must still be parsed");
}

#[test]
fn build_output_directories_are_skipped() {
    let (_dir, p) = project(&[
        ("src/Vault.sol", "contract Vault {}"),
        ("out/Vault.sol/Vault.json.sol", "contract Stale {}"),
        ("artifacts/Old.sol", "contract Stale2 {}"),
        ("cache/Cached.sol", "contract Stale3 {}"),
    ]);

    let names: Vec<&str> = p
        .contracts
        .contracts
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names, vec!["Vault"]);
}

#[test]
fn unparseable_file_does_not_stop_the_project() {
    let (_dir, p) = project(&[
        ("src/Good.sol", "contract Good {}"),
        ("src/Broken.sol", "contract { function ( unterminated"),
    ]);

    // tree-sitter is error-tolerant, so the broken file yields a unit either way.
    // What matters is that the good contract is still found.
    assert!(p.contracts.unique_by_name("Good").is_some());
}

#[test]
fn resolution_is_deterministic_across_loads() {
    let files: &[(&str, &str)] = &[
        ("src/A.sol", "import \"./B.sol\";\ncontract A is B {}"),
        ("src/B.sol", "import \"./C.sol\";\ncontract B is C {}"),
        ("src/C.sol", "contract C {}"),
    ];
    let dir = tempfile::tempdir().expect("temp dir");
    common::write_all(dir.path(), files);

    let describe = |p: &Project| -> Vec<String> {
        p.contracts
            .contracts
            .iter()
            .map(|c| format!("{}:{:?}:{:?}", c.name, c.unit, c.linearization))
            .collect()
    };

    let first = describe(&Project::load(dir.path()).expect("load"));
    let second = describe(&Project::load(dir.path()).expect("load"));
    assert_eq!(first, second, "project resolution is not deterministic");
}
