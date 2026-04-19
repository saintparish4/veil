// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Known-vulnerable patterns that both the line-number detector and the CFG
/// taint detector should flag. Every function here has a real vulnerability.
contract CfgTruePositive {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    // -----------------------------------------------------------------
    // 1. Classic reentrancy: call before state write, no guard
    //    External call at line N, state write at line N+2 — textbook.
    // -----------------------------------------------------------------
    function classicReentrancy(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount; // state write AFTER call
    }

    // -----------------------------------------------------------------
    // 2. State write after call in BOTH branches
    //    Regardless of condition, every path does call → state write.
    // -----------------------------------------------------------------
    function bothBranchesVulnerable(uint256 amount, bool flag) external {
        require(balances[msg.sender] >= amount, "insufficient");
        if (flag) {
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
            balances[msg.sender] -= amount;
        } else {
            (bool ok, ) = msg.sender.call{value: amount / 2}("");
            require(ok);
            balances[msg.sender] -= amount / 2;
        }
    }

    // -----------------------------------------------------------------
    // 3. Call in loop with state write after loop
    //    External call inside iteration + state change after loop body.
    // -----------------------------------------------------------------
    address[] public recipients;

    function loopVulnerable() external {
        uint256 share = address(this).balance / recipients.length;
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: share}("");
            require(ok);
        }
        balances[msg.sender] = 0; // state write after loop with calls
    }

    // -----------------------------------------------------------------
    // 4. Unchecked call return value — no require, no assignment
    // -----------------------------------------------------------------
    function uncheckedCall(address target) external {
        target.call("");
    }

    // -----------------------------------------------------------------
    // 5. Missing access control on selfdestruct
    // -----------------------------------------------------------------
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    // -----------------------------------------------------------------
    // 6. Unrestricted fund transfer to arbitrary address
    // -----------------------------------------------------------------
    function withdrawTo(address to) external {
        payable(to).transfer(address(this).balance);
    }

    // -----------------------------------------------------------------
    // Helper: deposit
    // -----------------------------------------------------------------
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
