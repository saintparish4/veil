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

use veil::project_facts::{ModifierFacts, ProjectFacts};

use crate::contracts::{Contract, ContractGraph, ContractId};
use crate::resolve::{Diagnostic, SourceUnitGraph};

/// A resolved project: the files, and the contract graph built over them.
pub struct Project {
    pub sources: SourceUnitGraph,
    pub contracts: ContractGraph,
}

impl Project {
    /// Parse and resolve every `.sol` file under `root`.
    pub fn load(root: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let sources = SourceUnitGraph::load(root.as_ref())?;
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

    /// Does the function named `name`, searched through `linearization`, check the
    /// caller and revert?
    ///
    /// This is the one level of delegation I follow. OpenZeppelin 5.x writes
    /// `modifier onlyOwner() { _checkOwner(); _; }`, so stopping at the modifier
    /// body would report the single most common access-control pattern in the
    /// ecosystem as uncontrolled. I deliberately do not recurse further: two-level
    /// delegation is rare, and an unbounded walk here would need cycle handling
    /// for no real gain.
    fn callee_gates_on_caller(&self, linearization: &[ContractId], name: &str) -> bool {
        linearization
            .iter()
            .filter_map(|id| self.contracts.get(*id))
            .flat_map(|c| c.functions.iter())
            .any(|f| f.name == name && f.references_caller && f.can_revert)
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

            let direct = decl.references_caller && decl.can_revert;
            let delegated = !direct
                && decl
                    .calls
                    .iter()
                    .any(|callee| self.callee_gates_on_caller(&start.linearization, callee));

            return Some(ModifierFacts {
                name: decl.name.clone(),
                declaring_contract: current.name.clone(),
                gates_on_caller: direct || delegated,
                can_revert: decl.can_revert,
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
