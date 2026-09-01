//! Multi-file Solidity project resolution.
//!
//! `veil` analyses one file at a time, which is the right default — it is what
//! keeps a scan under 10 ms per file. But a single file is missing most of what
//! decides whether its code is safe. `onlyOwner` is declared in an imported base,
//! `IVault` is declared in a third file, and the storage layout a proxy shares
//! with its implementation spans two.
//!
//! This crate answers the questions that need the whole tree: what files are
//! here, what do they import, what contracts do they declare, and what does each
//! contract actually inherit. It hands the answers back to `veil` through
//! [`veil::project_facts::ProjectFacts`], so detectors can consult cross-file
//! information without `veil` ever depending on this crate.
//!
//! ```no_run
//! use veil::ProjectFacts;
//! use veil_project::Project;
//!
//! let project = Project::load("./contracts")?;
//! // `auth` is real access control even though it is not named `only*`.
//! let facts = project.resolve_modifier("Vault", "auth");
//! assert!(facts.is_some_and(|f| f.gates_on_caller));
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Everything here degrades rather than fails. An import that points outside the
//! tree, a base contract declared in a dependency I was not given, an inheritance
//! hierarchy that cannot be linearized — each produces a [`Diagnostic`] and a
//! best-effort result, because refusing to analyse a project over one unresolved
//! path helps nobody.

#![deny(clippy::unwrap_used)]

pub mod contracts;
pub mod facts;
pub mod resolve;

pub use contracts::{
    Contract, ContractGraph, ContractId, ContractKind, FunctionDecl, ModifierDecl,
};
pub use facts::Project;
pub use resolve::{
    Diagnostic, Import, Layout, Remapping, SourceUnit, SourceUnitGraph, SourceUnitId,
};
