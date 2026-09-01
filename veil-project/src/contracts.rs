//! Contract declarations, inheritance resolution, and C3 linearization.
//!
//! This is where a modifier stops being a name and becomes a body I can read.
//! Per file, `onlyOwner` is a string that happens to start with "only". With the
//! declaration resolved through the inheritance chain, it is a body I can inspect
//! for an actual caller check — which is a different and much better question.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tree_sitter::Node;
use veil::ast_utils::{
    contract_name, find_nodes_of_kind, function_modifiers, function_name, function_visibility,
    get_call_target, get_member_access, node_text, CallTarget, CONTRACT_KINDS,
};
use veil::types::Visibility;

use crate::resolve::{Diagnostic, SourceUnitGraph, SourceUnitId};

/// Stable handle to a declared contract, interface, or library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractId(pub usize);

/// Which of the three contract-like declarations this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
}

/// A function as declared in one contract, before override resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDecl {
    pub name: String,
    /// Modifier names as invoked, in source order.
    pub modifiers: Vec<String>,
    pub visibility: Visibility,
    /// False for interface functions and `virtual` declarations with no body.
    pub has_body: bool,
    /// Body facts, kept for the same reason as on [`ModifierDecl`]: a modifier
    /// that delegates to `_checkOwner()` is only judgeable if I already know what
    /// `_checkOwner` does.
    pub references_caller: bool,
    pub can_revert: bool,
    pub line: usize,
}

/// A modifier as declared, with the properties I care about already extracted.
///
/// I compute these at load time rather than storing the node, because holding a
/// `Node<'a>` would tie the whole graph to the lifetime of every parsed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifierDecl {
    pub name: String,
    /// The body reads the caller — `msg.sender`, `_msgSender()`, or `tx.origin`.
    pub references_caller: bool,
    /// The body can abort the call: `require`, `revert`, `assert`, or an `if`
    /// guarding a revert. A modifier that cannot revert enforces nothing.
    pub can_revert: bool,
    /// Names called from the body, so I can follow one level of delegation.
    /// OpenZeppelin 5.x writes `modifier onlyOwner() { _checkOwner(); _; }`, and
    /// missing that would make this analysis useless on most real code.
    pub calls: Vec<String>,
    pub line: usize,
}

/// One contract, interface, or library, with its inheritance resolved.
#[derive(Debug, Clone)]
pub struct Contract {
    pub id: ContractId,
    pub name: String,
    pub kind: ContractKind,
    pub is_abstract: bool,
    pub unit: SourceUnitId,
    pub line: usize,
    /// Base names exactly as written, in source order (Solidity declares these
    /// most-base-first).
    pub base_names: Vec<String>,
    /// Bases I managed to resolve. Shorter than `base_names` when a base lives in
    /// a file outside the project root.
    pub bases: Vec<ContractId>,
    /// C3 linearization, most-derived first, including this contract at index 0.
    pub linearization: Vec<ContractId>,
    pub functions: Vec<FunctionDecl>,
    pub modifiers: Vec<ModifierDecl>,
}

/// Every contract in a project, wired together by inheritance.
pub struct ContractGraph {
    pub contracts: Vec<Contract>,
    /// Name to declarations. A `Vec` because two files may declare the same name,
    /// which is legal and common (every project has its own `IERC20`).
    by_name: BTreeMap<String, Vec<ContractId>>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Does this node read the caller's identity?
///
/// I walk member accesses rather than matching text so `msg.sender` inside a
/// comment or a revert string does not count. `_msgSender()` is checked as a call
/// because it is how every OpenZeppelin contract reads the caller under
/// meta-transactions.
fn references_caller(body: &Node, source: &str) -> bool {
    for kind in ["member_expression", "member_access_expression"] {
        for node in find_nodes_of_kind(body, kind) {
            if let Some((object, member)) = get_member_access(&node, source) {
                if (object == "msg" && member == "sender") || (object == "tx" && member == "origin")
                {
                    return true;
                }
            }
        }
    }
    call_names(body, source).iter().any(|n| n == "_msgSender")
}

/// Can this body abort the transaction?
///
/// `require`/`assert` show up as calls, `revert` as either a statement or a call
/// (`revert CustomError()` parses differently from `revert("msg")` across grammar
/// versions), so I check both shapes.
fn can_revert(body: &Node, source: &str) -> bool {
    if !find_nodes_of_kind(body, "revert_statement").is_empty() {
        return true;
    }
    call_names(body, source)
        .iter()
        .any(|n| matches!(n.as_str(), "require" | "revert" | "assert"))
}

/// Names of everything called in a body, innermost identifier only.
///
/// `_checkOwner()` yields `_checkOwner`; `IFoo(a).bar()` yields `bar`. That is
/// enough to follow delegation to an internal helper, which is all I use it for.
///
/// Goes through `get_call_target` rather than reading `call.child(0)` directly:
/// the grammar wraps a callee in a generic `expression` node (and in a
/// `struct_expression` for `addr.call{value: 1}(…)`), so the naive read finds a
/// wrapper instead of the name and silently reports no calls at all.
fn call_names(body: &Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for kind in ["call_expression", "function_call"] {
        for call in find_nodes_of_kind(body, kind) {
            match get_call_target(&call, source) {
                Some(CallTarget::FreeFunction { name }) => out.push(name.to_string()),
                Some(CallTarget::MemberCall { method, .. }) => out.push(method.to_string()),
                None => {}
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The `function_body` child of a function or modifier definition.
///
/// Indexed rather than iterated with a cursor: a `TreeCursor` borrow would have
/// to outlive the returned node, which it cannot when it is a local here.
fn definition_body<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    (0..node.child_count() as u32)
        .filter_map(|i| node.child(i))
        .find(|c| c.kind() == "function_body")
}

fn kind_of(node_kind: &str) -> ContractKind {
    match node_kind {
        "interface_declaration" => ContractKind::Interface,
        "library_declaration" => ContractKind::Library,
        _ => ContractKind::Contract,
    }
}

/// Base contract names from the `inheritance_specifier` children.
///
/// The grammar nests these as `inheritance_specifier > user_defined_type >
/// identifier`, and a base with constructor arguments (`Base(1)`) adds
/// `call_argument` siblings I skip. For a qualified name like `Lib.Base` the
/// user_defined_type holds several identifiers, so I take the last one.
fn base_names(contract_node: &Node, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for spec in find_nodes_of_kind(contract_node, "inheritance_specifier") {
        let types = find_nodes_of_kind(&spec, "user_defined_type");
        let Some(ty) = types.first() else { continue };
        let idents = find_nodes_of_kind(ty, "identifier");
        if let Some(last) = idents.last() {
            out.push(node_text(last, source).to_string());
        }
    }
    out
}

impl ContractGraph {
    /// Collect every declaration in the project, resolve bases, and linearize.
    pub fn build(graph: &SourceUnitGraph) -> Self {
        let mut contracts = Vec::new();
        let mut by_name: BTreeMap<String, Vec<ContractId>> = BTreeMap::new();
        let diagnostics = Vec::new();

        for unit in &graph.units {
            let root = unit.root();
            for kind in CONTRACT_KINDS {
                for node in find_nodes_of_kind(&root, kind) {
                    let Some(name) = contract_name(&node, &unit.source) else {
                        continue;
                    };
                    let id = ContractId(contracts.len());
                    let header = node_text(&node, &unit.source);
                    contracts.push(Contract {
                        id,
                        name: name.to_string(),
                        kind: kind_of(kind),
                        is_abstract: header.trim_start().starts_with("abstract"),
                        unit: unit.id,
                        line: node.start_position().row + 1,
                        base_names: base_names(&node, &unit.source),
                        bases: Vec::new(),
                        linearization: Vec::new(),
                        functions: collect_functions(&node, &unit.source),
                        modifiers: collect_modifiers(&node, &unit.source),
                    });
                    by_name.entry(name.to_string()).or_default().push(id);
                }
            }
        }

        let mut me = Self {
            contracts,
            by_name,
            diagnostics,
        };
        me.resolve_bases(graph);
        me.linearize_all(graph);
        me.diagnostics.sort();
        me.diagnostics.dedup();
        me
    }

    /// Turn base names into [`ContractId`]s.
    ///
    /// A name is looked up first in the declaring file, then in files it imports
    /// transitively, and only then across the whole project. The last step is a
    /// guess — two unrelated files can each declare `IERC20` — so I take the
    /// lowest id for determinism and say so in a diagnostic.
    fn resolve_bases(&mut self, graph: &SourceUnitGraph) {
        let mut resolved: Vec<(usize, Vec<ContractId>, Vec<Diagnostic>)> = Vec::new();

        for (idx, contract) in self.contracts.iter().enumerate() {
            let reachable = graph.transitive_imports(contract.unit);
            let mut bases = Vec::new();
            let mut diags = Vec::new();
            let file = graph
                .units
                .get(contract.unit.0)
                .map(|u| u.path.clone())
                .unwrap_or_default();

            for base in &contract.base_names {
                let Some(candidates) = self.by_name.get(base) else {
                    diags.push(Diagnostic {
                        file: file.clone(),
                        line: contract.line,
                        message: format!(
                            "base `{base}` of `{}` is not declared in the project",
                            contract.name
                        ),
                    });
                    continue;
                };
                let pick = candidates
                    .iter()
                    .find(|c| self.contracts[c.0].unit == contract.unit)
                    .or_else(|| {
                        candidates
                            .iter()
                            .find(|c| reachable.contains(&self.contracts[c.0].unit))
                    });
                match pick {
                    Some(id) => bases.push(*id),
                    None => {
                        // Not reachable by imports. Real projects do rely on the
                        // compiler seeing a file some other unit pulled in, so I
                        // take the first declaration rather than giving up.
                        if let Some(first) = candidates.first() {
                            bases.push(*first);
                            diags.push(Diagnostic {
                                file: file.clone(),
                                line: contract.line,
                                message: format!(
                                    "base `{base}` of `{}` resolved by name only; no import path reaches it",
                                    contract.name
                                ),
                            });
                        }
                    }
                }
            }
            resolved.push((idx, bases, diags));
        }

        for (idx, bases, diags) in resolved {
            self.contracts[idx].bases = bases;
            self.diagnostics.extend(diags);
        }
    }

    fn linearize_all(&mut self, graph: &SourceUnitGraph) {
        let mut results: Vec<(usize, Vec<ContractId>, Option<Diagnostic>)> = Vec::new();
        for (idx, contract) in self.contracts.iter().enumerate() {
            let mut guard = BTreeSet::new();
            match self.c3(contract.id, &mut guard) {
                Some(order) => results.push((idx, order, None)),
                None => {
                    // C3 failed: either an inheritance cycle or an ordering the
                    // algorithm cannot merge. Solidity would reject this, but I am
                    // not a compiler and refusing to analyse the file helps nobody.
                    // Depth-first order is a usable approximation, flagged as such.
                    let file = graph
                        .units
                        .get(contract.unit.0)
                        .map(|u| u.path.clone())
                        .unwrap_or_default();
                    results.push((
                        idx,
                        self.depth_first_order(contract.id),
                        Some(Diagnostic {
                            file,
                            line: contract.line,
                            message: format!(
                                "could not linearize `{}`; using depth-first base order",
                                contract.name
                            ),
                        }),
                    ));
                }
            }
        }
        for (idx, order, diag) in results {
            self.contracts[idx].linearization = order;
            if let Some(d) = diag {
                self.diagnostics.push(d);
            }
        }
    }

    /// C3 linearization, most-derived first.
    ///
    /// Solidity declares bases most-base-first (`contract C is A, B` means B wins
    /// a tie), so the direct bases are reversed before merging — that reversal is
    /// the whole difference between matching solc and not.
    ///
    /// `guard` carries the contracts currently being linearized, so an inheritance
    /// cycle returns `None` instead of recursing forever.
    fn c3(&self, id: ContractId, guard: &mut BTreeSet<ContractId>) -> Option<Vec<ContractId>> {
        if !guard.insert(id) {
            return None;
        }
        let contract = self.contracts.get(id.0)?;
        let bases_rev: Vec<ContractId> = contract.bases.iter().rev().copied().collect();

        let mut sequences: Vec<VecDeque<ContractId>> = Vec::new();
        for base in &bases_rev {
            sequences.push(self.c3(*base, guard)?.into());
        }
        if !bases_rev.is_empty() {
            sequences.push(bases_rev.iter().copied().collect());
        }

        guard.remove(&id);

        let mut result = vec![id];
        result.extend(merge(sequences)?);
        Some(result)
    }

    /// Fallback ordering when C3 cannot merge: this contract, then its bases
    /// depth-first, deduplicated. Cycle-safe via the visited set.
    fn depth_first_order(&self, id: ContractId) -> Vec<ContractId> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            out.push(current);
            if let Some(c) = self.contracts.get(current.0) {
                for base in c.bases.iter().rev() {
                    stack.push(*base);
                }
            }
        }
        out
    }

    /// Declarations of `name`, in declaration order.
    pub fn by_name(&self, name: &str) -> &[ContractId] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The single declaration of `name`, or `None` when absent or ambiguous.
    ///
    /// Ambiguity returns `None` on purpose: a caller asking about "the" contract
    /// named `IERC20` in a project with four of them should get no answer rather
    /// than an arbitrary one.
    pub fn unique_by_name(&self, name: &str) -> Option<&Contract> {
        match self.by_name(name) {
            [only] => self.contracts.get(only.0),
            _ => None,
        }
    }

    pub fn get(&self, id: ContractId) -> Option<&Contract> {
        self.contracts.get(id.0)
    }
}

/// Standard C3 merge: repeatedly take the head of some sequence that appears in
/// no other sequence's tail. `None` when no such head exists, which means the
/// hierarchy has no consistent linearization.
fn merge(mut sequences: Vec<VecDeque<ContractId>>) -> Option<Vec<ContractId>> {
    let mut out = Vec::new();
    loop {
        sequences.retain(|s| !s.is_empty());
        if sequences.is_empty() {
            return Some(out);
        }
        let candidate = sequences.iter().find_map(|seq| {
            let head = *seq.front()?;
            let in_tail = sequences
                .iter()
                .any(|other| other.iter().skip(1).any(|c| *c == head));
            (!in_tail).then_some(head)
        })?;
        out.push(candidate);
        for seq in &mut sequences {
            if seq.front() == Some(&candidate) {
                seq.pop_front();
            }
        }
    }
}

fn collect_functions(contract_node: &Node, source: &str) -> Vec<FunctionDecl> {
    find_nodes_of_kind(contract_node, "function_definition")
        .iter()
        .filter_map(|node| {
            let name = function_name(node, source)?;
            let body = definition_body(node);
            Some(FunctionDecl {
                name: name.to_string(),
                modifiers: function_modifiers(node, source)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                visibility: function_visibility(node, source),
                has_body: body.is_some(),
                references_caller: body.as_ref().is_some_and(|b| references_caller(b, source)),
                can_revert: body.as_ref().is_some_and(|b| can_revert(b, source)),
                line: node.start_position().row + 1,
            })
        })
        .collect()
}

fn collect_modifiers(contract_node: &Node, source: &str) -> Vec<ModifierDecl> {
    find_nodes_of_kind(contract_node, "modifier_definition")
        .iter()
        .filter_map(|node| {
            let mut cursor = node.walk();
            let name = node
                .named_children(&mut cursor)
                .find(|c| c.kind() == "identifier")
                .map(|n| node_text(&n, source).to_string())?;
            let body = definition_body(node);
            Some(ModifierDecl {
                name,
                references_caller: body.as_ref().is_some_and(|b| references_caller(b, source)),
                can_revert: body.as_ref().is_some_and(|b| can_revert(b, source)),
                calls: body
                    .as_ref()
                    .map(|b| call_names(b, source))
                    .unwrap_or_default(),
                line: node.start_position().row + 1,
            })
        })
        .collect()
}
