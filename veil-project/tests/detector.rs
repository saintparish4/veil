//! Running the real access-control detector with and without project facts.
//!
//! The unit tests prove the modifier resolution is correct. These prove it
//! changes what a user actually sees, which is the only claim worth making.
//!
//! Both fixtures below use `setImplementation`, which the detector treats as a
//! sensitive operation, inside an externally callable function.

mod common;

use common::project;
use veil::detector_trait::{AnalysisContext, Detector};
use veil::detectors::AccessControlDetector;
use veil::scan::new_solidity_parser;
use veil::types::Finding;
use veil_project::Project;

/// Real access control that the name heuristic rejects: MakerDAO's `auth`.
const AUTH_GUARDED: &str = r#"contract Auth {
    mapping(address => bool) public wards;
    address public implementation;

    modifier auth() {
        require(wards[msg.sender], "not authorized");
        _;
    }

    function upgradeTo(address impl) external auth {
        setImplementation(impl);
    }

    function setImplementation(address impl) internal {
        implementation = impl;
    }
}"#;

/// A time guard the name heuristic accepts because it starts with "only".
const TIME_GUARDED: &str = r#"contract Timed {
    uint256 public start;
    address public implementation;

    modifier onlyAfter(uint256 t) {
        if (block.timestamp < t) revert TooEarly();
        _;
    }

    function upgradeTo(address impl) external onlyAfter(start) {
        setImplementation(impl);
    }

    function setImplementation(address impl) internal {
        implementation = impl;
    }
}"#;

/// Run the detector over `source`, optionally handing it resolved project facts.
fn findings(source: &str, project: Option<&Project>) -> Vec<Finding> {
    let mut parser = new_solidity_parser().expect("solidity grammar");
    let tree = parser.parse(source, None).expect("parse");
    let ctx = AnalysisContext::new(&tree, source);
    let ctx = match project {
        Some(p) => ctx.with_project(p),
        None => ctx,
    };
    let mut out = Vec::new();
    AccessControlDetector.run(&ctx, &mut out);
    out
}

#[test]
fn project_facts_remove_the_auth_false_positive() {
    let (_dir, p) = project(&[("src/Auth.sol", AUTH_GUARDED)]);

    let without = findings(AUTH_GUARDED, None);
    assert!(
        !without.is_empty(),
        "fixture must trip the per-file heuristic, or this test proves nothing"
    );

    let with = findings(AUTH_GUARDED, Some(&p));
    assert!(
        with.is_empty(),
        "`auth` resolves to a msg.sender check, so the finding must disappear: {with:?}"
    );
}

#[test]
fn project_facts_expose_the_only_named_time_guard() {
    let (_dir, p) = project(&[("src/Timed.sol", TIME_GUARDED)]);

    let without = findings(TIME_GUARDED, None);
    assert!(
        without.is_empty(),
        "the name heuristic accepts `onlyAfter`, so nothing should be reported without facts"
    );

    let with = findings(TIME_GUARDED, Some(&p));
    assert!(
        !with.is_empty(),
        "`onlyAfter` gates on the clock, not the caller — this function is unprotected"
    );
}

#[test]
fn inherited_guard_from_another_file_is_respected() {
    // The case that motivated all of this: the modifier is not in the file being
    // analysed, so per file there is nothing to read but the name.
    let base = r#"contract Ownable {
    address public owner;
    modifier restricted() {
        require(msg.sender == owner, "not owner");
        _;
    }
}"#;
    let vault = r#"import "./Ownable.sol";
contract Vault is Ownable {
    address public implementation;
    function upgradeTo(address impl) external restricted {
        setImplementation(impl);
    }
    function setImplementation(address impl) internal {
        implementation = impl;
    }
}"#;
    let (_dir, p) = project(&[("src/Ownable.sol", base), ("src/Vault.sol", vault)]);

    assert!(
        !findings(vault, None).is_empty(),
        "`restricted` is not named `only*`, so the per-file check flags it"
    );
    assert!(
        findings(vault, Some(&p)).is_empty(),
        "with the base resolved, `restricted` is clearly a caller check"
    );
}

#[test]
fn unresolvable_modifier_falls_back_instead_of_flipping() {
    // The base is outside the project. `is_access_controlled` returns None, and
    // the detector must keep its old behaviour rather than treat the missing
    // answer as "unprotected".
    let vault = r#"contract Vault is ExternalBase {
    address public implementation;
    function upgradeTo(address impl) external onlyOwner {
        setImplementation(impl);
    }
    function setImplementation(address impl) internal {
        implementation = impl;
    }
}"#;
    let (_dir, p) = project(&[("src/Vault.sol", vault)]);

    assert_eq!(
        findings(vault, None).len(),
        findings(vault, Some(&p)).len(),
        "an unresolved modifier must not change the verdict"
    );
}

#[test]
fn inline_sender_check_still_wins_without_any_modifier() {
    // Project facts only speak about modifiers, so a bare require must keep
    // working with facts attached.
    let source = r#"contract Direct {
    address public owner;
    address public implementation;
    function upgradeTo(address impl) external {
        require(msg.sender == owner, "not owner");
        setImplementation(impl);
    }
    function setImplementation(address impl) internal {
        implementation = impl;
    }
}"#;
    let (_dir, p) = project(&[("src/Direct.sol", source)]);

    assert!(findings(source, None).is_empty());
    assert!(findings(source, Some(&p)).is_empty());
}
