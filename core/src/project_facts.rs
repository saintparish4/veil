//! Cross-file facts a detector can consult when one is available.
//!
//! Detectors run per file, and a single file rarely contains everything needed to
//! judge it. `onlyOwner` is usually declared in an imported base contract, so a
//! per-file analysis can only match on the modifier's *name* and hope. That guess
//! is wrong in both directions: `auth` and `requiresAuth` are real access control
//! that a name check misses, and `onlyWhenActive` is not access control at all but
//! a name check accepts it.
//!
//! [`ProjectFacts`] is the escape hatch. It is declared here, in `core`, and
//! implemented by `veil-project`, which keeps the dependency direction intact —
//! `core` never learns about project resolution, it just accepts answers from
//! something that did the work.
//!
//! Every method returns `Option`/`Vec` so "I could not resolve that" is
//! representable. A detector that gets `None` must fall back to its existing
//! per-file behaviour rather than assuming the answer is negative.

/// What I know about a modifier after resolving it through the inheritance chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifierFacts {
    /// Name of the modifier as invoked.
    pub name: String,
    /// Contract that actually declares the body, which is often not the contract
    /// the modifier is used in.
    pub declaring_contract: String,
    /// The body gates on caller identity — `msg.sender` compared against stored
    /// state, a role check, or a call to an authority contract.
    ///
    /// This is the field that replaces the `starts_with("only")` guess.
    pub gates_on_caller: bool,
    /// The body can abort the call at all (`require`, `revert`, or `if (…) revert`).
    /// A modifier that cannot revert cannot be enforcing anything.
    pub can_revert: bool,
}

/// Facts derived from a resolved multi-file project.
///
/// Implemented by `veil-project`. `Send + Sync` so a shared reference can be
/// handed to detectors running across rayon workers.
pub trait ProjectFacts: Send + Sync {
    /// Resolve a modifier invoked inside `contract` to its declaration, searching
    /// the contract itself and then its linearized bases.
    ///
    /// `None` means I could not find a declaration — the modifier may come from a
    /// file outside the project root, so callers must not read this as "does not exist".
    fn resolve_modifier(&self, contract: &str, modifier: &str) -> Option<ModifierFacts>;

    /// Whether `function` in `contract` is access controlled, judged by resolving
    /// every modifier it carries.
    ///
    /// `Some(false)` is a positive claim that none of the modifiers gate on the
    /// caller. `None` means at least one modifier could not be resolved, so I have
    /// no opinion.
    fn is_access_controlled(&self, contract: &str, function: &str) -> Option<bool>;

    /// Contracts in the project that inherit from `name`, sorted for determinism.
    fn implementations_of(&self, name: &str) -> Vec<String>;

    /// C3 linearization of `contract`, most-derived first, as declared names.
    /// Empty if the contract is unknown.
    fn linearization(&self, contract: &str) -> Vec<String>;
}
