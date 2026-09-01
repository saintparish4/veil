//! Resolving modifiers to their bodies, which is the whole reason this crate exists.
//!
//! Each test names a modifier that the per-file name heuristic
//! (`starts_with("only")`) gets wrong, and pins the answer I give instead.

mod common;

use common::project;
use veil::ProjectFacts;

/// The base every fixture below inherits from, mirroring how real projects get
/// their access control: declared in an imported file, never in the contract
/// being analysed.
const OWNABLE: &str = r#"
contract Ownable {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    modifier onlyAfter(uint256 t) {
        if (block.timestamp < t) revert TooEarly();
        _;
    }

    modifier noop() {
        _;
    }

    bool public paused;
}
"#;

fn with_ownable(vault: &str) -> Vec<(&'static str, String)> {
    vec![
        ("src/Ownable.sol", OWNABLE.to_string()),
        (
            "src/Vault.sol",
            format!("import \"./Ownable.sol\";\n{vault}"),
        ),
    ]
}

fn load(vault: &str) -> (tempfile::TempDir, veil_project::Project) {
    let owned = with_ownable(vault);
    let files: Vec<(&str, &str)> = owned.iter().map(|(p, c)| (*p, c.as_str())).collect();
    project(&files)
}

#[test]
fn inherited_modifier_resolves_across_files() {
    // The headline case: `onlyOwner` is declared in Ownable.sol, used in
    // Vault.sol, and a per-file analysis can only see the name.
    let (_dir, p) = load("contract Vault is Ownable { function rescue() external onlyOwner {} }");

    let facts = p
        .resolve_modifier("Vault", "onlyOwner")
        .expect("onlyOwner should resolve through the base");
    assert_eq!(facts.declaring_contract, "Ownable");
    assert!(facts.gates_on_caller);
    assert!(facts.can_revert);
}

#[test]
fn auth_style_modifier_is_recognised_despite_its_name() {
    // MakerDAO uses `auth`, Solmate uses `requiresAuth`. Neither starts with
    // "only", so the name heuristic reports these functions as unprotected —
    // a false positive on some of the most-audited code in the ecosystem.
    let (_dir, p) = project(&[(
        "src/Auth.sol",
        r#"contract Auth {
            mapping(address => bool) public wards;
            modifier auth() { require(wards[msg.sender], "not authorized"); _; }
            function file(uint256 v) external auth {}
        }"#,
    )]);

    let facts = p.resolve_modifier("Auth", "auth").expect("auth resolves");
    assert!(
        facts.gates_on_caller,
        "`auth` gates on msg.sender and must be recognised"
    );
    assert_eq!(p.is_access_controlled("Auth", "file"), Some(true));
}

#[test]
fn openzeppelin_five_delegation_is_followed() {
    // OZ 5.x moved the check out of the modifier:
    //     modifier onlyOwner() { _checkOwner(); _; }
    // Stopping at the modifier body would report the single most common access
    // control pattern in Solidity as uncontrolled.
    let (_dir, p) = project(&[(
        "src/Oz.sol",
        r#"contract Ownable {
            address private _owner;
            function owner() public view returns (address) { return _owner; }
            function _checkOwner() internal view {
                if (owner() != msg.sender) revert OwnableUnauthorizedAccount(msg.sender);
            }
            modifier onlyOwner() { _checkOwner(); _; }
        }
        contract Vault is Ownable {
            function sweep() external onlyOwner {}
        }"#,
    )]);

    let facts = p
        .resolve_modifier("Vault", "onlyOwner")
        .expect("resolves through the base");
    assert!(
        facts.gates_on_caller,
        "delegation to _checkOwner() must be followed"
    );
    assert_eq!(p.is_access_controlled("Vault", "sweep"), Some(true));
}

#[test]
fn time_guard_named_only_is_not_access_control() {
    // `onlyAfter` starts with "only" so the name heuristic accepts it, but it
    // gates on the clock, not the caller. Treating it as access control silences
    // the detector on a genuinely unprotected function.
    let (_dir, p) = load("contract Vault is Ownable { function claim() external onlyAfter(1) {} }");

    let facts = p
        .resolve_modifier("Vault", "onlyAfter")
        .expect("onlyAfter resolves");
    assert!(
        !facts.gates_on_caller,
        "a timestamp guard is not access control"
    );
    assert!(facts.can_revert, "it does revert, just not on the caller");
    assert_eq!(p.is_access_controlled("Vault", "claim"), Some(false));
}

#[test]
fn pause_guard_is_not_access_control() {
    // `whenNotPaused` is in core's hardcoded accept-list today. It stops everyone
    // equally, which is the opposite of an authorization check.
    let (_dir, p) =
        load("contract Vault is Ownable { function deposit() external whenNotPaused {} }");

    let facts = p
        .resolve_modifier("Vault", "whenNotPaused")
        .expect("resolves");
    assert!(!facts.gates_on_caller);
    assert_eq!(p.is_access_controlled("Vault", "deposit"), Some(false));
}

#[test]
fn modifier_that_cannot_revert_enforces_nothing() {
    let (_dir, p) = load("contract Vault is Ownable { function ping() external noop {} }");

    let facts = p.resolve_modifier("Vault", "noop").expect("resolves");
    assert!(!facts.can_revert);
    assert!(!facts.gates_on_caller);
}

#[test]
fn derived_override_wins_over_base() {
    // Most-derived-first traversal means a contract that redefines a modifier
    // gets its own body, not its base's.
    let (_dir, p) = project(&[(
        "src/Override.sol",
        r#"contract Base { modifier guard() { require(msg.sender == address(1)); _; } }
           contract Weak is Base { modifier guard() { _; } function f() external guard {} }"#,
    )]);

    let facts = p.resolve_modifier("Weak", "guard").expect("resolves");
    assert_eq!(facts.declaring_contract, "Weak");
    assert!(
        !facts.gates_on_caller,
        "the derived, weakened body is the one that runs"
    );
}

#[test]
fn unresolvable_modifier_returns_no_opinion() {
    // The base lives in a dependency I was never given. `None` is the honest
    // answer; claiming the function is unprotected would be a false positive.
    let (_dir, p) = project(&[(
        "src/Vault.sol",
        "contract Vault is SomeExternalBase { function f() external mysteryGuard {} }",
    )]);

    assert!(p.resolve_modifier("Vault", "mysteryGuard").is_none());
    assert_eq!(
        p.is_access_controlled("Vault", "f"),
        None,
        "an unresolved modifier must not be read as absent"
    );
}

#[test]
fn function_with_no_modifiers_is_a_definite_negative() {
    let (_dir, p) = load("contract Vault is Ownable { function open() external {} }");
    assert_eq!(p.is_access_controlled("Vault", "open"), Some(false));
}

#[test]
fn caller_check_in_a_comment_or_string_does_not_count() {
    // The reason references_caller walks member-access nodes instead of matching
    // text. Both of these mention msg.sender and neither checks it.
    let (_dir, p) = project(&[(
        "src/Sneaky.sol",
        r#"contract Sneaky {
            // require(msg.sender == owner) would go here
            modifier commented() { revert("msg.sender is not the owner"); }
            function f() external commented {}
        }"#,
    )]);

    let facts = p.resolve_modifier("Sneaky", "commented").expect("resolves");
    assert!(
        !facts.gates_on_caller,
        "msg.sender in a comment or revert string is not a caller check"
    );
    assert!(facts.can_revert);
}

#[test]
fn msg_sender_without_a_revert_is_not_a_gate() {
    // Reading the caller is not the same as checking it.
    let (_dir, p) = project(&[(
        "src/Log.sol",
        r#"contract Log {
            event Seen(address who);
            modifier logged() { emit Seen(msg.sender); _; }
            function f() external logged {}
        }"#,
    )]);

    let facts = p.resolve_modifier("Log", "logged").expect("resolves");
    assert!(!facts.gates_on_caller);
    assert!(!facts.can_revert);
    assert_eq!(p.is_access_controlled("Log", "f"), Some(false));
}

#[test]
fn unknown_contract_yields_no_opinion() {
    let (_dir, p) = load("contract Vault is Ownable {}");
    assert!(p.resolve_modifier("NotAContract", "onlyOwner").is_none());
    assert_eq!(p.is_access_controlled("NotAContract", "f"), None);
}

#[test]
fn openzeppelin_only_role_two_hop_delegation_is_followed() {
    // Found by running against OpenZeppelin v5.0.2, where the naive one-body rule
    // called `onlyRole` "not access control". The caller read and the revert live
    // in different functions, one hop apart:
    //   onlyRole -> _checkRole(role) -> _checkRole(role, _msgSender())
    let (_dir, p) = project(&[(
        "src/AccessControl.sol",
        r#"contract AccessControl {
            mapping(bytes32 => mapping(address => bool)) private _roles;
            function hasRole(bytes32 role, address account) public view returns (bool) {
                return _roles[role][account];
            }
            function _checkRole(bytes32 role) internal view {
                _checkRole(role, _msgSender());
            }
            function _checkRole(bytes32 role, address account) internal view {
                if (!hasRole(role, account)) {
                    revert AccessControlUnauthorizedAccount(account, role);
                }
            }
            function _msgSender() internal view returns (address) { return msg.sender; }
            modifier onlyRole(bytes32 role) { _checkRole(role); _; }
        }
        contract Vault is AccessControl {
            function upgradeTo(address impl) external onlyRole(0x00) {}
        }"#,
    )]);

    let facts = p
        .resolve_modifier("Vault", "onlyRole")
        .expect("onlyRole resolves");
    assert!(
        facts.gates_on_caller,
        "onlyRole is the most widely deployed role guard in Solidity; calling it \
         uncontrolled would false-positive on every protocol that uses AccessControl"
    );
    assert_eq!(p.is_access_controlled("Vault", "upgradeTo"), Some(true));
}

#[test]
fn access_managed_restricted_delegation_is_followed() {
    // OpenZeppelin 5's AccessManaged: the caller read is in the modifier, the
    // revert is one hop down. The mirror image of the onlyRole shape.
    let (_dir, p) = project(&[(
        "src/Managed.sol",
        r#"contract AccessManaged {
            modifier restricted() { _checkCanCall(msg.sender, msg.sig); _; }
            function _checkCanCall(address caller, bytes4 selector) internal view {
                if (!canCall(caller, selector)) revert AccessManagedUnauthorized(caller);
            }
            function canCall(address a, bytes4 s) public view returns (bool) { return false; }
        }
        contract Target is AccessManaged {
            function admin() external restricted {}
        }"#,
    )]);

    assert!(
        p.resolve_modifier("Target", "restricted")
            .expect("resolves")
            .gates_on_caller
    );
}

#[test]
fn reentrancy_and_pause_guards_are_still_not_access_control() {
    // The transitive walk must not become so permissive that it accepts anything
    // that reverts somewhere. These three all delegate, and none check the caller.
    let (_dir, p) = project(&[(
        "src/Guards.sol",
        r#"contract Guards {
            uint256 private _status;
            bool private _paused;
            modifier nonReentrant() { _nonReentrantBefore(); _; }
            function _nonReentrantBefore() private {
                if (_status == 2) revert ReentrancyGuardReentrantCall();
                _status = 2;
            }
            modifier whenNotPaused() { _requireNotPaused(); _; }
            function _requireNotPaused() internal view {
                if (_paused) revert EnforcedPause();
            }
            modifier initializer() { _checkInitializing(); _; }
            function _checkInitializing() internal view {
                if (_initialized) revert InvalidInitialization();
            }
            bool private _initialized;
        }"#,
    )]);

    for name in ["nonReentrant", "whenNotPaused", "initializer"] {
        let facts = p.resolve_modifier("Guards", name).expect("resolves");
        assert!(
            !facts.gates_on_caller,
            "`{name}` reverts, but not based on who called it"
        );
        assert!(facts.can_revert);
    }
}

#[test]
fn delegation_depth_is_bounded() {
    // A chain longer than the cap, plus mutual recursion, must terminate and not
    // silently claim a guard exists.
    let (_dir, p) = project(&[(
        "src/Deep.sol",
        r#"contract Deep {
            modifier guard() { a(); _; }
            function a() internal view { b(); }
            function b() internal view { c(); }
            function c() internal view { d(); }
            function d() internal view { if (msg.sender == address(0)) revert(); }
            modifier loop() { x(); _; }
            function x() internal view { y(); }
            function y() internal view { x(); }
        }"#,
    )]);

    // Terminating at all is the assertion that matters for `loop`.
    assert!(
        !p.resolve_modifier("Deep", "loop")
            .expect("resolves")
            .gates_on_caller
    );
    // `d` sits four hops from the modifier body, past the cap.
    assert!(
        !p.resolve_modifier("Deep", "guard")
            .expect("resolves")
            .gates_on_caller
    );
}
