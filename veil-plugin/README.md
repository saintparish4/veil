# veil-plugin

Public API for authoring **custom [Veil](../README.md) detectors** as Rust code,
without forking the scanner. A plugin detector implements the same `Detector`
trait as the built-in detectors and gets the same analysis surface: the parsed
AST, the control-flow graph, taint queries, inter-procedural summaries, DeFi
pattern helpers, and the storage-layout model.

For predicate-style checks that don't need Rust (function name / modifier / body
matches), prefer TOML rules in `.veil/rules/` instead — see the
[*Custom Rules*](../README.md#custom-rules) section of the project README.

## Add the crate

Add `veil-plugin` as a workspace dependency and put your detector in its own
member crate:

```toml
# Your project's Cargo.toml
[workspace]
members = ["contracts", "my-detectors"]

[workspace.dependencies]
veil-plugin = { git = "https://github.com/saintparish4/veil" }
```

## Implement a detector

```rust
use veil_plugin::{AnalysisContext, Confidence, Detector, Finding, Severity};

pub struct MyDetector;

impl Detector for MyDetector {
    fn id(&self) -> &'static str { "my-custom-check" }
    fn name(&self) -> &'static str { "My Custom Check" }
    fn severity(&self) -> Severity { Severity::High }
    fn owasp_category(&self) -> Option<&'static str> { None }

    fn run(&self, ctx: &AnalysisContext<'_>, findings: &mut Vec<Finding>) {
        for func in &ctx.functions {
            // Inspect func via ctx.source, ctx.cfg_for(func), the summaries,
            // and the helpers re-exported below — then push Finding values.
        }
    }
}
```

Register it before scanning:

```rust
registry.register(Box::new(MyDetector));
```

## What the crate re-exports

Everything a plugin author needs is re-exported from `veil-plugin` so you depend
on this crate alone:

| Group | Items |
|-------|-------|
| Core trait + context | `Detector`, `AnalysisContext`, `DetectorRegistry` |
| Findings | `Finding`, `Severity`, `Confidence` |
| Control-flow graph | `ControlFlowGraph`, `BasicBlock`, `CfgStatement`, `CallMeta`, `StorageOp`, `GuardKind`, … |
| Taint analysis | `find_taint_violations`, `TaintQuery`, `TaintViolation`, `CfgStatementKind` |
| DeFi patterns | `classify_contract_role`, `has_cei_pattern`, `is_erc4626_vault`, `is_flash_loan_receiver`, `is_uniswap_callback`, `is_proxy_upgrade_function`, `ContractRole` |
| Inter-procedural | `FunctionSummary` |
| Storage model | `build_storage_model`, `StorageModel`, `StorageSlot` |
| AST utilities | `find_nodes_of_kind`, `node_text`, `function_name`, `function_modifiers`, `get_call_target`, `is_external_call`, `is_state_write`, `is_view_or_pure`, `func_body`, `CallTarget` |
| Pattern rule engine | `parse_predicate`, `eval_predicate`, `run_pattern_rules`, `PatternRule`, `Predicate` |

## API stability

```rust
pub const API_VERSION: u32 = 1;
```

`API_VERSION` is bumped on breaking changes to the plugin interface. Assert it at
startup to fail fast against an incompatible Veil version:

```rust
pub const VEIL_PLUGIN_API_VERSION: u32 = veil_plugin::API_VERSION;
```

## See also

- [`core/src/detectors/README.md`](../core/src/detectors/README.md) — the built-in
  detector development guide (the `Detector` trait, `AnalysisContext` fields, and
  the AST utility reference all apply to plugins too).
- [Project README](../README.md) — CLI, output formats, and TOML `.veil/rules/`.

## License

MIT © Sharif Parish
