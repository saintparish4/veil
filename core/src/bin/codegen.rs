use ts_rs::{Config, TS};
use veil::types::{
    Confidence, Finding, ScanError, ScanErrorKind, ScanOutcome, Severity, Statistics,
};

fn main() {
    let out_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../web/types.generated.ts");

    let cfg = Config::default();
    let mut out = String::new();
    out.push_str("// Auto-GENERATED -- do not edit manually\n");
    out.push_str("// Regenerate: cargo run --features codegen --bin codegen\n\n");

    out.push_str(&format!("export {};\n\n", Severity::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", Confidence::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", Finding::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", Statistics::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", ScanErrorKind::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", ScanError::decl(&cfg)));
    out.push_str(&format!("export {};\n\n", ScanOutcome::decl(&cfg)));

    std::fs::write(&out_path, &out).expect("failed to write types.generated.ts");
    println!("types.generated.ts written to {}", out_path.display());
}
