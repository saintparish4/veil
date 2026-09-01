//! Answering `core`'s [`ProjectFacts`] questions from the resolved graph.
//!
//! The one that matters is [`Project::resolve_modifier`]. Everything upstream of
//! it exists so that this can stop guessing from a name:
//!
//! | Modifier | Name check says | I say | Who is right |
//! |---|---|---|---|
//! | `onlyOwner { require(msg.sender == owner); _; }` | controlled | controlled | tie |
//! | `onlyOwner { _checkOwner(); _; }` (OpenZeppelin 5) | controlled | controlled | tie |
//! | `auth { require(isAuthorized(msg.sender)); _; }` | **not** controlled | controlled | me |
//! | `onlyAfter(t) { if (block.timestamp < t) revert; _; }` | controlled | **not** | me |
//! | `whenNotPaused { require(!paused); _; }` | controlled | **not** | me |
//!
//! Rows three through five are the false positives and false negatives the name
//! check produces today, and they are exactly the modifiers real protocols use.

use std::collections::BTreeSet;

use veil::project_facts::{ModifierFacts, ProjectFacts};

use crate::contracts::{Contract, ContractGraph, ContractId, ModifierDecl};

/// How far to follow a modifier's internal calls looking for a caller check.
///
/// Three covers every pattern I have found in production: OpenZeppelin's
/// `onlyRole` needs two hops, `AccessManaged.restricted` needs one, and a direct
/// `require(msg.sender == owner)` needs none.
const MAX_DELEGATION_DEPTH: usize = 3;
use crate::resolve::{Diagnostic, LoadOptions, SourceUnitGraph};

/// A resolved project: the files, and the contract graph built over them.
pub struct Project {
    pub sources: SourceUnitGraph,
    pub contracts: ContractGraph,
}

impl Project {
    /// Parse and resolve every `.sol` file under `root`.
    pub fn load(root: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Self::load_with(root, LoadOptions::default())
    }

    /// As [`load`](Self::load), with control over what is reported.
    pub fn load_with(
        root: impl AsRef<std::path::Path>,
        options: LoadOptions,
    ) -> std::io::Result<Self> {
        let sources = SourceUnitGraph::load_with(root.as_ref(), options)?;
        let contracts = ContractGraph::build(&sources);
        Ok(Self { sources, contracts })
    }

    /// Everything I could not resolve, from both resolution stages, sorted.
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut all = self.sources.diagnostics.clone();
        all.extend(self.contracts.diagnostics.iter().cloned());
        all.sort();
        all.dedup();
        all
    }

    /// Look up a contract by name, refusing ambiguous names.
    fn contract(&self, name: &str) -> Option<&Contract> {
        self.contracts.unique_by_name(name)
    }

    /// What a modifier can do, following its internal calls.
    ///
    /// Returns `(reads the caller, can revert)` over the modifier body plus
    /// everything reachable from it. Both have to be transitive, because real
    /// guards almost never do the work inline.
    ///
    /// The naive version asks whether one body both reads the caller and reverts.
    /// OpenZeppelin's `onlyRole` is the counterexample that proves it wrong:
    ///
    /// ```text
    /// modifier onlyRole(bytes32 role) { _checkRole(role); _; }
    /// function _checkRole(bytes32 role)                  { _checkRole(role, _msgSender()); }
    /// function _checkRole(bytes32 role, address account) { if (!hasRole(...)) revert ...; }
    /// ```
    ///
    /// The caller read is one hop down and the revert is two, so no single body
    /// has both, and the naive check calls the most widely deployed role guard in
    /// Solidity "not access control" — a false positive on every `onlyRole`
    /// guarded sensitive function.
    ///
    /// This is deliberately loose: I do not prove the caller value flows into the
    /// revert condition. Loose here errs toward silence, which is the right
    /// direction, because the failure mode of being strict is inventing
    /// missing-access-control findings on correctly guarded code.
    ///
    /// Bounded at [`MAX_DELEGATION_DEPTH`] with a visited set, so a long chain
    /// costs little and mutual recursion terminates.
    fn reachable_facts(&self, linearization: &[ContractId], decl: &ModifierDecl) -> (bool, bool) {
        let mut saw_caller = decl.references_caller;
        let mut saw_revert = decl.can_revert;
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut frontier: Vec<String> = decl.calls.clone();

        for _ in 0..MAX_DELEGATION_DEPTH {
            if saw_caller && saw_revert {
                break;
            }
            let mut next = Vec::new();
            for name in std::mem::take(&mut frontier) {
                if !visited.insert(name.clone()) {
                    continue;
                }
                // Every overload of the name, since declarations are keyed by name
                // alone — and for `_checkRole` the two overloads are exactly where
                // the caller read and the revert live.
                for f in linearization
                    .iter()
                    .filter_map(|id| self.contracts.get(*id))
                    .flat_map(|c| c.functions.iter())
                    .filter(|f| f.name == name)
                {
                    saw_caller |= f.references_caller;
                    saw_revert |= f.can_revert;
                    next.extend(f.calls.iter().cloned());
                }
            }
            frontier = next;
        }
        (saw_caller, saw_revert)
    }
}

impl ProjectFacts for Project {
    fn resolve_modifier(&self, contract: &str, modifier: &str) -> Option<ModifierFacts> {
        let start = self.contract(contract)?;

        // Walk most-derived first so an override wins, which is what solc does.
        for id in &start.linearization {
            let Some(current) = self.contracts.get(*id) else {
                continue;
            };
            let Some(decl) = current.modifiers.iter().find(|m| m.name == modifier) else {
                continue;
            };

            let (reads_caller, can_revert) = self.reachable_facts(&start.linearization, decl);
            return Some(ModifierFacts {
                name: decl.name.clone(),
                declaring_contract: current.name.clone(),
                gates_on_caller: reads_caller && can_revert,
                can_revert,
            });
        }
        None
    }

    fn is_access_controlled(&self, contract: &str, function: &str) -> Option<bool> {
        let start = self.contract(contract)?;

        // Most-derived declaration with a body is the one that actually runs.
        let decl = start
            .linearization
            .iter()
            .filter_map(|id| self.contracts.get(*id))
            .flat_map(|c| c.functions.iter())
            .find(|f| f.name == function && f.has_body)?;

        if decl.modifiers.is_empty() {
            // A positive claim about modifiers only. An inline
            // `require(msg.sender == owner)` is still the caller's job to check,
            // which is why the detector consults this *alongside* its own body
            // analysis rather than instead of it.
            return Some(false);
        }

        let mut any_unresolved = false;
        for name in &decl.modifiers {
            match self.resolve_modifier(contract, name) {
                Some(facts) if facts.gates_on_caller => return Some(true),
                Some(_) => {}
                None => any_unresolved = true,
            }
        }

        // If a modifier came from a file outside the project I have no opinion,
        // rather than claiming the function is unprotected.
        if any_unresolved {
            None
        } else {
            Some(false)
        }
    }

    fn implementations_of(&self, name: &str) -> Vec<String> {
        let Some(target) = self.contract(name) else {
            return Vec::new();
        };
        let mut out: Vec<String> = self
            .contracts
            .contracts
            .iter()
            .filter(|c| c.id != target.id && c.linearization.contains(&target.id))
            .map(|c| c.name.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn linearization(&self, contract: &str) -> Vec<String> {
        let Some(start) = self.contract(contract) else {
            return Vec::new();
        };
        start
            .linearization
            .iter()
            .filter_map(|id| self.contracts.get(*id))
            .map(|c| c.name.clone())
            .collect()
    }
}
