// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Safe patterns that a line-number-based reentrancy detector incorrectly flags.
/// CFG taint analysis should produce zero reentrancy findings on every function.
contract CfgFalsePositiveRegression {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // -----------------------------------------------------------------
    // 1. Correct checks-effects-interactions (CEI) pattern
    //    State is updated BEFORE the call — safe.
    // -----------------------------------------------------------------
    function withdrawCEI(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // -----------------------------------------------------------------
    // 2. State write in else-only branch (unreachable from call path)
    //    Call is in the if-branch; state write is in the else-branch.
    //    No path goes through both.
    // -----------------------------------------------------------------
    function branchedSafe(bool flag) external {
        if (flag) {
            (bool ok, ) = msg.sender.call{value: 1}("");
            require(ok);
        } else {
            balances[msg.sender] = 0;
        }
    }

    // -----------------------------------------------------------------
    // 3. External call inside if-block with early return
    //    After the call the function returns; the state write below
    //    is unreachable on the call path.
    // -----------------------------------------------------------------
    function earlyReturnSafe(uint256 amount) external {
        if (amount > 0) {
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
            return;
        }
        balances[msg.sender] = 0;
    }

    // -----------------------------------------------------------------
    // 4. Multiple calls with correctly interleaved state changes
    //    Each state change happens BEFORE its associated call.
    // -----------------------------------------------------------------
    function interleavedSafe(uint256 a, uint256 b) external {
        balances[msg.sender] -= a;
        (bool ok1, ) = msg.sender.call{value: a}("");
        require(ok1);

        balances[msg.sender] -= b;
        (bool ok2, ) = msg.sender.call{value: b}("");
        require(ok2);
    }

    // -----------------------------------------------------------------
    // 5. view function with staticcall — cannot modify state
    // -----------------------------------------------------------------
    function querySafe(address target) external view returns (bytes memory) {
        (bool ok, bytes memory data) = target.staticcall("");
        require(ok);
        return data;
    }

    // -----------------------------------------------------------------
    // 6. nonReentrant modifier protects the function
    // -----------------------------------------------------------------
    function withdrawGuarded(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    // -----------------------------------------------------------------
    // 7. Internal function — not externally callable
    // -----------------------------------------------------------------
    function _internalTransfer(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
        balances[to] += amount;
    }

    // -----------------------------------------------------------------
    // 8. Pure computational function — no external call at all
    // -----------------------------------------------------------------
    function computeHash(uint256 x) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(x));
    }

    // -----------------------------------------------------------------
    // 9. State write guarded by require before call
    //    require acts as sanitizer: if it reverts, call never happens.
    // -----------------------------------------------------------------
    function guardedWrite(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    // -----------------------------------------------------------------
    // 10. Event emission after call (not a state write)
    //     Emitting an event is not a state modification vulnerability.
    // -----------------------------------------------------------------
    event Withdrawn(address indexed user, uint256 amount);

    function withdrawWithEvent(uint256 amount) external {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        emit Withdrawn(msg.sender, amount);
    }

    // -----------------------------------------------------------------
    // 11. Call result captured and checked on next line
    //     Return value is assigned — not an unchecked call.
    // -----------------------------------------------------------------
    function capturedReturn(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "call failed");
    }

    receive() external payable {}
}
