//! TOML-based pattern rule engine.
//!
//! Teams write pattern rules in `.veil/rules/*.toml`:
//!
//! ```toml
//! [[rules]]
//! type = "pattern"
//! id = "custom-timelock"
//! severity = "High"
//! pattern = "function_name_contains('schedule') AND NOT has_modifier('onlyProposer')"
//! message = "Timelock schedule without proposer access control"
//! ```
//!
//! Rules are evaluated per function; any function that matches the predicate emits a finding.
//!
//! # Predicate grammar
//!
//! ```text
//! expr    = or_expr
//! or_expr = and_expr ( "OR" and_expr )*
//! and_expr = not_expr ( "AND" not_expr )*
//! not_expr = "NOT" atom | atom
//! atom    = "(" expr ")" | predicate_call
//! predicate_call = name "(" "'" value "'" ")"
//!
//! Supported predicates:
//!   function_name_contains('str')    — function name contains str (case-insensitive)
//!   has_modifier('name')             — function has the named modifier
//!   body_contains('str')             — function body source contains str (case-insensitive)
//!   is_external                      — function has external visibility
//!   is_public                        — function has public visibility
//! ```

use crate::ast_utils::{function_modifiers, function_name, is_view_or_pure, node_text};
use crate::types::{Confidence, Finding, Severity};
use serde::Deserialize;
use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Pattern rule type (loaded from TOML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct PatternRule {
    pub id: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub pattern: String,
    pub message: String,
    #[serde(default)]
    pub suggestion: String,
}

fn default_severity() -> String {
    "Medium".to_string()
}

impl PatternRule {
    pub fn severity_parsed(&self) -> Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "low" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Predicate {
    FunctionNameContains(String),
    HasModifier(String),
    BodyContains(String),
    IsExternal,
    IsPublic,
    IsViewOrPure,
    And(Box<Predicate>, Box<Predicate>),
    Or(Box<Predicate>, Box<Predicate>),
    Not(Box<Predicate>),
}

// ---------------------------------------------------------------------------
// Parser (recursive descent)
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len()
            && self.input[self.pos..].starts_with(|c: char| c.is_ascii_whitespace())
        {
            self.pos += 1;
        }
    }

    fn peek_word(&self) -> &str {
        let rem = &self.input[self.pos..];
        let end = rem
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rem.len());
        &rem[..end]
    }

    fn consume_word(&mut self) -> &str {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap_or('\0');
            if c.is_alphanumeric() || c == '_' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        &self.input[start..self.pos]
    }

    fn consume_char(&mut self, ch: char) -> Result<(), String> {
        self.skip_ws();
        if self.remaining().starts_with(ch) {
            self.pos += ch.len_utf8();
            Ok(())
        } else {
            Err(format!(
                "Expected '{}' at position {} in: {}",
                ch,
                self.pos,
                self.input
            ))
        }
    }

    /// Parse a single-quoted string argument: `'value'`
    fn parse_string_arg(&mut self) -> Result<String, String> {
        self.consume_char('(')?;
        self.skip_ws();
        self.consume_char('\'')?;
        let start = self.pos;
        while self.pos < self.input.len() {
            if self.remaining().starts_with('\'') {
                break;
            }
            self.pos += 1;
        }
        let value = self.input[start..self.pos].to_string();
        self.consume_char('\'')?;
        self.skip_ws();
        self.consume_char(')')?;
        Ok(value)
    }

    fn parse_atom(&mut self) -> Result<Predicate, String> {
        self.skip_ws();
        if self.remaining().starts_with('(') {
            self.pos += 1;
            let inner = self.parse_expr()?;
            self.consume_char(')')?;
            return Ok(inner);
        }
        let word = self.peek_word().to_string();
        match word.as_str() {
            "NOT" => {
                self.consume_word();
                self.skip_ws();
                let inner = self.parse_atom()?;
                Ok(Predicate::Not(Box::new(inner)))
            }
            "function_name_contains" => {
                self.consume_word();
                Ok(Predicate::FunctionNameContains(self.parse_string_arg()?))
            }
            "has_modifier" => {
                self.consume_word();
                Ok(Predicate::HasModifier(self.parse_string_arg()?))
            }
            "body_contains" => {
                self.consume_word();
                Ok(Predicate::BodyContains(self.parse_string_arg()?))
            }
            "is_external" => {
                self.consume_word();
                Ok(Predicate::IsExternal)
            }
            "is_public" => {
                self.consume_word();
                Ok(Predicate::IsPublic)
            }
            "is_view_or_pure" => {
                self.consume_word();
                Ok(Predicate::IsViewOrPure)
            }
            _ => Err(format!(
                "Unknown predicate '{}' at position {} in: {}",
                word, self.pos, self.input
            )),
        }
    }

    fn parse_not_expr(&mut self) -> Result<Predicate, String> {
        self.skip_ws();
        if self.peek_word() == "NOT" {
            self.consume_word();
            self.skip_ws();
            let inner = self.parse_atom()?;
            Ok(Predicate::Not(Box::new(inner)))
        } else {
            self.parse_atom()
        }
    }

    fn parse_and_expr(&mut self) -> Result<Predicate, String> {
        let mut left = self.parse_not_expr()?;
        loop {
            self.skip_ws();
            if self.peek_word() == "AND" {
                self.consume_word();
                let right = self.parse_not_expr()?;
                left = Predicate::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_expr(&mut self) -> Result<Predicate, String> {
        let mut left = self.parse_and_expr()?;
        loop {
            self.skip_ws();
            if self.peek_word() == "OR" {
                self.consume_word();
                let right = self.parse_and_expr()?;
                left = Predicate::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }
}

/// Parse a pattern expression string into a `Predicate` AST.
///
/// Returns `Err` with a human-readable message on parse failure.
pub fn parse_predicate(input: &str) -> Result<Predicate, String> {
    let mut p = Parser::new(input.trim());
    let pred = p.parse_expr()?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(format!(
            "Unexpected trailing input at position {}: '{}'",
            p.pos,
            &p.input[p.pos..]
        ));
    }
    Ok(pred)
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Evaluate a `Predicate` against a `function_definition` node.
pub fn eval_predicate(pred: &Predicate, func: &Node, source: &str) -> bool {
    match pred {
        Predicate::FunctionNameContains(s) => {
            let name = function_name(func, source).unwrap_or("").to_lowercase();
            name.contains(&s.to_lowercase())
        }
        Predicate::HasModifier(m) => {
            let mods = function_modifiers(func, source);
            mods.iter().any(|mod_name| mod_name.eq_ignore_ascii_case(m))
        }
        Predicate::BodyContains(s) => {
            let text = node_text(func, source).to_lowercase();
            text.contains(&s.to_lowercase())
        }
        Predicate::IsExternal => {
            let text = node_text(func, source);
            text.contains("external")
        }
        Predicate::IsPublic => {
            let text = node_text(func, source);
            text.contains("public")
        }
        Predicate::IsViewOrPure => is_view_or_pure(func, source),
        Predicate::And(l, r) => eval_predicate(l, func, source) && eval_predicate(r, func, source),
        Predicate::Or(l, r) => eval_predicate(l, func, source) || eval_predicate(r, func, source),
        Predicate::Not(inner) => !eval_predicate(inner, func, source),
    }
}

// ---------------------------------------------------------------------------
// Run pattern rules against a set of functions
// ---------------------------------------------------------------------------

/// Evaluate all pattern rules against the functions in `source` and return findings.
pub fn run_pattern_rules(
    rules: &[PatternRule],
    functions: &[Node],
    source: &str,
    file_path: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        let pred = match parse_predicate(&rule.pattern) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(rule_id = %rule.id, error = %e, "Failed to parse pattern rule");
                continue;
            }
        };

        for func in functions {
            if eval_predicate(&pred, func, source) {
                let line = func.start_position().row + 1;
                let mut finding = Finding {
                    id: String::new(),
                    detector_id: rule.id.clone(),
                    severity: rule.severity_parsed(),
                    confidence: Confidence::Medium,
                    line,
                    vulnerability_type: "PatternRule".to_string(),
                    message: rule.message.clone(),
                    suggestion: rule.suggestion.clone(),
                    remediation: None,
                    owasp_category: None,
                    file: file_path.map(|s| s.to_string()),
                };
                finding.compute_id();
                findings.push(finding);
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Path-level scan (used from main.rs)
// ---------------------------------------------------------------------------

/// Run pattern rules against all `.sol` files under `path`.
///
/// If `path` is a single file, runs against that file only.
/// If `path` is a directory, scans `*.sol` files (recursively if `recursive = true`).
pub fn run_pattern_rules_on_path(
    rules: &[PatternRule],
    path: &str,
    recursive: bool,
) -> Vec<Finding> {
    use crate::scan::new_solidity_parser;
    use std::path::Path;
    use walkdir::WalkDir;

    let mut all_findings = Vec::new();

    let mut parser = match new_solidity_parser() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("pattern rules: failed to create parser: {}", e);
            return all_findings;
        }
    };

    let paths: Vec<_> = if Path::new(path).is_dir() {
        let walker = WalkDir::new(path).max_depth(if recursive { usize::MAX } else { 1 });
        walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext == "sol")
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![Path::new(path).to_path_buf()]
    };

    for file_path in &paths {
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };
        let ctx = crate::detector_trait::AnalysisContext::new(&tree, &source)
            .with_file_path(file_path.to_str().unwrap_or(""));

        let file_str = file_path.to_str();
        let mut findings = run_pattern_rules(rules, &ctx.functions, &source, file_str);
        all_findings.append(&mut findings);
    }

    all_findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::new_solidity_parser;

    fn parse_ok(input: &str) -> Predicate {
        parse_predicate(input).expect("should parse")
    }

    #[test]
    fn parse_single_predicate() {
        let pred = parse_ok("function_name_contains('withdraw')");
        assert!(matches!(pred, Predicate::FunctionNameContains(s) if s == "withdraw"));
    }

    #[test]
    fn parse_and() {
        let pred = parse_ok("function_name_contains('swap') AND NOT has_modifier('nonReentrant')");
        assert!(matches!(pred, Predicate::And(_, _)));
    }

    #[test]
    fn parse_or_and_nesting() {
        let pred =
            parse_ok("is_external OR (function_name_contains('admin') AND NOT has_modifier('onlyOwner'))");
        assert!(matches!(pred, Predicate::Or(_, _)));
    }

    #[test]
    fn parse_not() {
        let pred = parse_ok("NOT is_view_or_pure");
        assert!(matches!(pred, Predicate::Not(_)));
    }

    #[test]
    fn parse_error_unknown_predicate() {
        assert!(parse_predicate("unknown_pred('x')").is_err());
    }

    #[test]
    fn parse_error_trailing_input() {
        assert!(parse_predicate("is_external blah").is_err());
    }

    fn get_funcs<'a>(tree: &'a tree_sitter::Tree, src: &'a str) -> Vec<tree_sitter::Node<'a>> {
        crate::ast_utils::find_nodes_of_kind(&tree.root_node(), "function_definition")
    }

    #[test]
    fn eval_function_name_contains() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function withdrawAll() external {}
    function deposit() external {}
}"#;
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(src, None).expect("parse");
        let funcs = get_funcs(&tree, src);

        let pred = parse_ok("function_name_contains('withdraw')");
        let matches: Vec<_> = funcs
            .iter()
            .filter(|f| eval_predicate(&pred, f, src))
            .collect();
        assert_eq!(matches.len(), 1, "only withdrawAll should match");
    }

    #[test]
    fn eval_has_modifier() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    modifier onlyOwner() { _; }
    function setFee() external onlyOwner {}
    function publicFunc() external {}
}"#;
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(src, None).expect("parse");
        let funcs = get_funcs(&tree, src);

        let pred = parse_ok("NOT has_modifier('onlyOwner')");
        let unprotected: Vec<_> = funcs
            .iter()
            .filter(|f| eval_predicate(&pred, f, src))
            .collect();
        assert_eq!(unprotected.len(), 1, "only publicFunc should lack onlyOwner");
    }

    #[test]
    fn eval_and_compound() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    modifier nonReentrant() { _; }
    function swap() external {}
    function safeSwap() external nonReentrant {}
}"#;
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(src, None).expect("parse");
        let funcs = get_funcs(&tree, src);

        let pred = parse_ok("function_name_contains('swap') AND NOT has_modifier('nonReentrant')");
        let flagged: Vec<_> = funcs
            .iter()
            .filter(|f| eval_predicate(&pred, f, src))
            .collect();
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            function_name(&flagged[0], src).unwrap_or(""),
            "swap"
        );
    }

    #[test]
    fn run_pattern_rules_emits_finding() {
        let src = r#"pragma solidity ^0.8.0;
contract C {
    function setOwner(address a) external {}
}"#;
        let rules = vec![PatternRule {
            id: "test-no-owner-guard".to_string(),
            severity: "High".to_string(),
            pattern: "function_name_contains('setOwner') AND NOT has_modifier('onlyOwner')"
                .to_string(),
            message: "setOwner missing access control".to_string(),
            suggestion: String::new(),
        }];
        let mut parser = new_solidity_parser().expect("parser");
        let tree = parser.parse(src, None).expect("parse");
        let ctx = crate::detector_trait::AnalysisContext::new(&tree, src);
        let findings = run_pattern_rules(&rules, &ctx.functions, src, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
