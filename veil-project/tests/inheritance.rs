//! C3 linearization and cross-file base resolution.
//!
//! The ordering assertions here are the ones that have to match solc exactly.
//! Solidity declares bases most-base-first, so `contract D is B, C` means C wins
//! a tie — get the reversal wrong and every override resolves to the wrong body.

mod common;

use common::{contract, project};
use veil::ProjectFacts;
use veil_project::ContractKind;

#[test]
fn single_chain_linearizes_most_derived_first() {
    let (_dir, p) = project(&[(
        "src/Chain.sol",
        "contract A {} contract B is A {} contract C is B {}",
    )]);
    assert_eq!(p.linearization("C"), vec!["C", "B", "A"]);
    assert_eq!(p.linearization("B"), vec!["B", "A"]);
    assert_eq!(p.linearization("A"), vec!["A"]);
}

#[test]
fn multiple_bases_reverse_declaration_order() {
    // `is A, B` — B is the more derived of the two, so it comes first.
    let (_dir, p) = project(&[(
        "src/Multi.sol",
        "contract A {} contract B {} contract C is A, B {}",
    )]);
    assert_eq!(p.linearization("C"), vec!["C", "B", "A"]);
}

#[test]
fn diamond_inheritance_matches_c3() {
    // The canonical case. A naive depth-first walk would produce [D, B, A, C],
    // putting A ahead of C and resolving overrides to the wrong implementation.
    let (_dir, p) = project(&[(
        "src/Diamond.sol",
        "contract A {} contract B is A {} contract C is A {} contract D is B, C {}",
    )]);
    assert_eq!(p.linearization("D"), vec!["D", "C", "B", "A"]);
}

#[test]
fn inheritance_across_files_resolves() {
    let (_dir, p) = project(&[
        (
            "src/Vault.sol",
            "import \"./base/Ownable.sol\";\ncontract Vault is Ownable {}",
        ),
        ("src/base/Ownable.sol", "contract Ownable {}"),
    ]);
    assert_eq!(p.linearization("Vault"), vec!["Vault", "Ownable"]);
    assert!(p.diagnostics().is_empty(), "{:?}", p.diagnostics());
}

#[test]
fn base_with_constructor_arguments_resolves() {
    // `Base(1)` adds `call_argument` children the base-name extraction must skip.
    let (_dir, p) = project(&[(
        "src/Args.sol",
        "contract Base { constructor(uint x) {} } contract Derived is Base(1) {}",
    )]);
    assert_eq!(p.linearization("Derived"), vec!["Derived", "Base"]);
}

#[test]
fn interfaces_and_libraries_are_collected() {
    let (_dir, p) = project(&[(
        "src/Kinds.sol",
        "interface IVault { function f() external; }
         library Math { function add(uint a) internal pure returns (uint) { return a; } }
         contract Vault is IVault { function f() external override {} }",
    )]);

    assert_eq!(contract(&p, "IVault").kind, ContractKind::Interface);
    assert_eq!(contract(&p, "Math").kind, ContractKind::Library);
    assert_eq!(contract(&p, "Vault").kind, ContractKind::Contract);
    assert_eq!(p.linearization("Vault"), vec!["Vault", "IVault"]);
}

#[test]
fn abstract_contracts_are_flagged() {
    let (_dir, p) = project(&[(
        "src/Abstract.sol",
        "abstract contract Base { function f() public virtual; } contract Impl is Base { function f() public override {} }",
    )]);
    assert!(contract(&p, "Base").is_abstract);
    assert!(!contract(&p, "Impl").is_abstract);
}

#[test]
fn inheritance_cycle_does_not_hang() {
    // solc rejects this outright. I am not a compiler, so I degrade to a
    // best-effort order and say so rather than looping or refusing the project.
    let (_dir, p) = project(&[("src/Cycle.sol", "contract A is B {} contract B is A {}")]);

    let diags = p.diagnostics();
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("could not linearize")),
        "{diags:?}"
    );
    // Still answers, and still puts the contract itself first.
    assert_eq!(p.linearization("A").first().map(String::as_str), Some("A"));
}

#[test]
fn unknown_base_is_a_diagnostic() {
    let (_dir, p) = project(&[("src/Lonely.sol", "contract Vault is NotHere {}")]);

    let diags = p.diagnostics();
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("is not declared in the project")),
        "{diags:?}"
    );
    assert_eq!(p.linearization("Vault"), vec!["Vault"]);
}

#[test]
fn implementations_of_lists_descendants() {
    let (_dir, p) = project(&[(
        "src/Impls.sol",
        "interface IVault {} contract VaultA is IVault {} contract VaultB is IVault {} contract Unrelated {}",
    )]);

    assert_eq!(p.implementations_of("IVault"), vec!["VaultA", "VaultB"]);
    assert!(p.implementations_of("Unrelated").is_empty());
}

#[test]
fn ambiguous_contract_name_yields_no_answer() {
    // Two files each declaring `IERC20` is normal. Picking one arbitrarily would
    // make results depend on directory order, so I decline to answer instead.
    let (_dir, p) = project(&[
        (
            "src/a/IERC20.sol",
            "interface IERC20 { function a() external; }",
        ),
        (
            "src/b/IERC20.sol",
            "interface IERC20 { function b() external; }",
        ),
    ]);

    assert_eq!(p.contracts.by_name("IERC20").len(), 2);
    assert!(p.contracts.unique_by_name("IERC20").is_none());
    assert!(p.linearization("IERC20").is_empty());
}
