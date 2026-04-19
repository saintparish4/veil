use clap::{Parser, Subcommand};
use colored::*;
use std::path::Path;
use veil::detectors::build_registry;
use veil::scan::{exit_code_for_stats, new_solidity_parser};
use veil::*;

#[derive(Parser)]
#[command(name = "veil")]
#[command(about = "Smart contract security scanner for Solidity", long_about = None)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Enable verbose output: detector decisions, skipped files, suppressed findings.
    /// Equivalent to setting RUST_LOG=debug.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: String,
        #[arg(short, long, default_value = "terminal")]
        format: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        baseline: Option<String>,
        /// Generate a report in the given format (html or pdf)
        /// Output is written to stdout; redirect to a file:
        /// veil scan contracts/ --recursive --report html > report.html
        #[arg(long, value_name = "FORMAT", value_parser = ["html", "pdf"])]
        report: Option<String>,
        /// Path to a logo image (PNG, SVG, JPEG) for white-label reports
        #[arg(long, value_name = "PATH")]
        logo: Option<String>,
        /// Organization name displayed in the report header
        #[arg(long = "org-name", value_name = "NAME")]
        org_name: Option<String>,
    },
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    // RUST_LOG overrides --verbose if set; otherwise verbose → debug, default → warn.
    let default_level = if verbose { "debug" } else { "warn" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Commands::Scan {
            path,
            format,
            recursive,
            baseline,
            report,
            logo,
            org_name,
        } => {
            let mut parser = match new_solidity_parser() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let registry = build_registry();
            let outcome = if Path::new(&path).is_dir() {
                scan_directory_with(&path, recursive, &registry, &mut parser)
            } else {
                scan_file_with(&path, &registry, &mut parser)
            };

            for err in &outcome.errors {
                eprintln!("{} {} — {}", "Error:".red().bold(), err.file, err.message);
            }

            let mut findings = outcome.findings;

            if let Some(ref baseline_path) = baseline {
                let baseline_set = load_baseline(baseline_path);
                findings = filter_findings_by_baseline(findings, &baseline_set);
            }

            let stats = calculate_statistics(&findings);

            if let Some(ref report_format) = report {
                use veil::report::{HtmlReport, PdfReport, ReportConfig, ReportGenerator};
                let config = ReportConfig {
                    logo_path: logo,
                    org_name,
                };
                let result: Result<String, _> = match report_format.as_str() {
                    "html" => HtmlReport.generate(&path, &findings, &stats, &config),
                    "pdf" => PdfReport.generate(&path, &findings, &stats, &config),
                    other => {
                        eprintln!(
                            "{} Unknown report format '{}'. Use html or pdf.",
                            "Error:".red().bold(),
                            other
                        );
                        std::process::exit(1);
                    }
                };
                match result {
                    Ok(output) => print!("{}", output),
                    Err(e) => {
                        eprintln!("{} {}", "Report error:".red().bold(), e);
                        std::process::exit(1);
                    }
                }
            } else {
                match format.as_str() {
                    "json" => print_json(&findings, &stats),
                    "sarif" => print_sarif(&findings),
                    _ => print_results(&path, &findings, &stats),
                }
            }

            std::process::exit(exit_code_for_stats(&stats));
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use veil::detector_trait::{AnalysisContext, Detector};
    use veil::detectors::*;
    use veil::scan::new_solidity_parser;
    use veil::*;

    fn parse_solidity(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_solidity::LANGUAGE.into())
            .expect("Solidity language");
        parser.parse(source, None).expect("parse")
    }

    fn run_detector(detector: &dyn Detector, source: &str) -> Vec<Finding> {
        let tree = parse_solidity(source);
        let ctx = AnalysisContext::new(&tree, source);
        let mut findings = Vec::new();
        detector.run(&ctx, &mut findings);
        findings
    }

    fn test_finding(
        severity: Severity,
        confidence: Confidence,
        line: usize,
        vuln_type: &str,
        file: Option<&str>,
    ) -> Finding {
        Finding {
            id: String::new(),
            detector_id: String::new(),
            severity,
            confidence,
            line,
            vulnerability_type: vuln_type.to_string(),
            message: String::new(),
            suggestion: String::new(),
            remediation: None,
            owasp_category: None,
            file: file.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_self_service_function_names() {
        assert!(is_self_service_function_name("withdraw"));
        assert!(is_self_service_function_name("withdrawAll"));
        assert!(is_self_service_function_name("claim"));
        assert!(is_self_service_function_name("claimRewards"));
        assert!(is_self_service_function_name("stake"));
        assert!(is_self_service_function_name("deposit"));

        assert!(!is_self_service_function_name("setOwner"));
        assert!(!is_self_service_function_name("pause"));
        assert!(!is_self_service_function_name("initialize"));
    }

    #[test]
    fn test_self_service_pattern() {
        let safe_withdraw = r#"
            function withdraw() public {
                uint256 amt = balances[msg.sender];
                balances[msg.sender] = 0;
                payable(msg.sender).transfer(amt);
            }
        "#;
        assert!(is_self_service_pattern(safe_withdraw));

        let unsafe_withdraw = r#"
            function withdraw(address to, uint256 amount) public {
                balances[to] -= amount;
                payable(to).transfer(amount);
            }
        "#;
        assert!(!is_self_service_pattern(unsafe_withdraw));
    }

    #[test]
    fn test_visibility_detection() {
        assert_eq!(
            get_function_visibility("function foo() public { }"),
            Visibility::Public
        );
        assert_eq!(
            get_function_visibility("function foo() external { }"),
            Visibility::External
        );
        assert_eq!(
            get_function_visibility("function foo() internal { }"),
            Visibility::Internal
        );
        assert_eq!(
            get_function_visibility("function foo() private { }"),
            Visibility::Private
        );
    }

    #[test]
    fn test_visibility_confidence_adjustment() {
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Public),
            Confidence::High
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Private),
            Confidence::Low
        );
        assert_eq!(
            visibility_adjusted_confidence(Confidence::High, Visibility::Internal),
            Confidence::Medium
        );
    }

    // ========== Detector tests ==========

    #[test]
    fn detector_reentrancy_finds_state_change_after_call() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
        let findings = run_detector(&ReentrancyDetector, source);
        assert!(
            !findings.is_empty(),
            "reentrancy detector should find state change after call"
        );
        let f = &findings[0];
        assert_eq!(f.vulnerability_type, "Reentrancy");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detector_id, "reentrancy");
        assert!(f.owasp_category.is_some());
    }

    #[test]
    fn detector_tx_origin_finds_auth_use() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    address owner;
    function withdraw() public {
        require(tx.origin == owner);
    }
}
"#;
        let findings = run_detector(&TxOriginDetector, source);
        assert!(
            !findings.is_empty(),
            "tx.origin detector should find auth use"
        );
        assert_eq!(findings[0].vulnerability_type, "tx.origin Authentication");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].detector_id, "tx-origin");
    }

    #[test]
    fn detector_timestamp_dependence_finds_modulo() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function claim() public {
        require(block.timestamp % 15 == 0);
    }
}
"#;
        let findings = run_detector(&TimestampDetector, source);
        assert!(
            !findings.is_empty(),
            "timestamp detector should find modulo use"
        );
        assert_eq!(findings[0].vulnerability_type, "Timestamp Dependence");
    }

    #[test]
    fn detector_unsafe_random_finds_block_properties() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function lottery() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % 100;
    }
}
"#;
        let findings = run_detector(&UnsafeRandomDetector, source);
        assert!(
            !findings.is_empty(),
            "unsafe random detector should find block-based randomness"
        );
        assert_eq!(findings[0].vulnerability_type, "Unsafe Randomness");
    }

    #[test]
    fn detector_access_control_finds_sensitive_without_auth() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function withdrawAll(address to) public {
        (bool ok,) = payable(to).call{value: address(this).balance}("");
        require(ok);
    }
}
"#;
        let findings = run_detector(&AccessControlDetector, source);
        assert!(
            !findings.is_empty(),
            "access control detector should find withdraw with arbitrary recipient"
        );
        assert_eq!(
            findings[0].vulnerability_type, "Unrestricted Fund Transfer",
            "expected Unrestricted Fund Transfer when withdraw allows arbitrary address"
        );
    }

    #[test]
    fn detector_unchecked_erc20_flags_transfer_without_check() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function pay(address token, address to, uint256 amt) public {
        IERC20(token).transfer(to, amt);
    }
}
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }
"#;
        let findings = run_detector(&UncheckedErc20Detector, source);
        assert!(
            !findings.is_empty(),
            "unchecked ERC20 detector should find transfer without check"
        );
        let vuln_type = &findings[0].vulnerability_type;
        assert!(
            vuln_type.contains("ERC20") || vuln_type.contains("SafeERC20"),
            "expected ERC20-related finding, got: {}",
            vuln_type
        );
    }

    #[test]
    fn detector_dangerous_delegatecall_finds_user_controlled_target() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function execute(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
"#;
        let findings = run_detector(&DangerousDelegatecallDetector, source);
        assert!(
            !findings.is_empty(),
            "delegatecall detector should find user-controlled target"
        );
        assert_eq!(findings[0].vulnerability_type, "Dangerous Delegatecall");
    }

    #[test]
    fn detector_unchecked_call_finds_call_without_assignment() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function forward(address payable to) public {
        to.call{value: address(this).balance}("");
    }
}
"#;
        let findings = run_detector(&UncheckedCallsDetector, source);
        assert!(
            !findings.is_empty(),
            "unchecked call detector should find .call without return check"
        );
        assert_eq!(findings[0].vulnerability_type, "Unchecked Call");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn detector_integer_overflow_flags_unchecked_block() {
        let source = r#"
pragma solidity ^0.7.0;
contract C {
    function sub(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a - b;
        }
    }
}
"#;
        let findings = run_detector(&IntegerOverflowDetector, source);
        assert!(
            !findings.is_empty(),
            "integer overflow detector should find unchecked arithmetic in <0.8 or unchecked block"
        );
        let vt = &findings[0].vulnerability_type;
        assert!(
            vt == "Integer Overflow/Underflow" || vt == "Unchecked Arithmetic",
            "expected overflow-related finding, got: {}",
            vt
        );
    }

    #[test]
    fn detector_no_false_positive_on_self_service_withdraw() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok);
    }
}
"#;
        let findings = run_detector(&AccessControlDetector, source);
        assert!(
            findings.is_empty(),
            "access control should not flag self-service withdraw (operates on msg.sender only)"
        );
    }

    // ========== FP-absence tests ==========

    #[test]
    fn fp_absence_reentrancy_checks_effects_interactions() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) balances;
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
"#;
        let findings = run_detector(&ReentrancyDetector, source);
        assert!(
            findings.is_empty(),
            "CEI pattern should not trigger reentrancy"
        );
    }

    #[test]
    fn fp_absence_tx_origin_non_auth_use() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    event Origin(address indexed o);
    function logOrigin() public {
        emit Origin(tx.origin);
    }
}
"#;
        let findings = run_detector(&TxOriginDetector, source);
        assert!(
            findings.is_empty(),
            "tx.origin used for logging (not auth) should not trigger"
        );
    }

    #[test]
    fn fp_absence_timestamp_gte_comparison() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    uint256 public deadline;
    function check() public view returns (bool) {
        return block.timestamp >= deadline;
    }
}
"#;
        let findings = run_detector(&TimestampDetector, source);
        assert!(
            findings.is_empty(),
            ">= comparison with block.timestamp should not trigger"
        );
    }

    #[test]
    fn fp_absence_unchecked_erc20_safe_transfer() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function pay(address token, address to, uint256 amt) public {
        IERC20(token).safeTransfer(to, amt);
    }
}
"#;
        let findings = run_detector(&UncheckedErc20Detector, source);
        assert!(
            findings.is_empty(),
            "safeTransfer should not trigger unchecked ERC20"
        );
    }

    #[test]
    fn fp_absence_flash_loan_validated_callback() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    address public lender;
    function flashLoanCallback(uint256 amount) external {
        require(msg.sender == lender);
    }
}
"#;
        let findings = run_detector(&FlashLoanDetector, source);
        let callback_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability_type == "Unvalidated Callback")
            .collect();
        assert!(
            callback_findings.is_empty(),
            "validated callback should not trigger"
        );
    }

    #[test]
    fn fp_absence_delegatecall_with_access_control() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    address public owner;
    function execute(address target, bytes memory data) public {
        require(msg.sender == owner);
        target.delegatecall(data);
    }
}
"#;
        let findings = run_detector(&DangerousDelegatecallDetector, source);
        assert!(
            findings.is_empty(),
            "delegatecall with access control should not trigger"
        );
    }

    #[test]
    fn fp_absence_unchecked_call_with_bool_capture() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function forward(address payable to) public {
        (bool ok, ) = to.call{value: 1}("");
        require(ok);
    }
}
"#;
        let findings = run_detector(&UncheckedCallsDetector, source);
        assert!(
            findings.is_empty(),
            "checked call should not trigger unchecked call detector"
        );
    }

    #[test]
    fn fp_absence_integer_overflow_solidity_08() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"#;
        let findings = run_detector(&IntegerOverflowDetector, source);
        assert!(
            findings.is_empty(),
            "Solidity >=0.8 safe arithmetic should not trigger"
        );
    }

    #[test]
    fn fp_absence_access_control_self_service_claim() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    mapping(address => uint256) public rewards;
    function claim() public {
        uint256 r = rewards[msg.sender];
        rewards[msg.sender] = 0;
        payable(msg.sender).transfer(r);
    }
}
"#;
        let findings = run_detector(&AccessControlDetector, source);
        assert!(
            findings.is_empty(),
            "self-service claim should not trigger access control"
        );
    }

    #[test]
    fn fp_absence_unsafe_random_chainlink_vrf() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function requestRandomness() public {
        uint256 requestId = COORDINATOR.requestRandomWords(keyHash, subId, 3, 100000, 1);
    }
}
"#;
        let findings = run_detector(&UnsafeRandomDetector, source);
        assert!(
            findings.is_empty(),
            "VRF pattern should not trigger unsafe randomness"
        );
    }

    #[test]
    fn fp_absence_dos_loops_bounded() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    uint256 constant MAX_ITERATIONS = 100;
    address[] public users;
    function distribute() public {
        uint256 limit = users.length < MAX_ITERATIONS ? users.length : MAX_ITERATIONS;
        for (uint256 i = 0; i < limit; i++) {
            payable(users[i]).transfer(1);
        }
    }
}
"#;
        let findings = run_detector(&DosLoopsDetector, source);
        let unbounded: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability_type == "Unbounded Loop")
            .collect();
        assert!(
            unbounded.is_empty(),
            "bounded loop (MAX_) should not trigger unbounded loop detector"
        );
    }

    #[test]
    fn fp_absence_front_running_with_slippage() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function swap(uint256 amountIn, uint256 amountOutMin, uint256 deadline) external {
        require(block.timestamp <= deadline);
    }
}
"#;
        let findings = run_detector(&FrontRunningDetector, source);
        let slippage: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability_type == "Missing Slippage Protection")
            .collect();
        assert!(
            slippage.is_empty(),
            "swap with amountOutMin+deadline should not trigger missing slippage"
        );
    }

    #[test]
    fn fp_absence_storage_collision_with_gap() {
        let source = r#"
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract C is Initializable, Upgradeable {
    uint256 public value;
    uint256[50] private __gap;
    function initialize(uint256 v) external initializer {
        value = v;
    }
}
"#;
        let findings = run_detector(&StorageCollisionDetector, source);
        let gap: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability_type == "Missing Storage Gap")
            .collect();
        assert!(
            gap.is_empty(),
            "contract with __gap should not trigger missing storage gap"
        );
    }

    // ========== Integration test: full scan ==========

    #[test]
    fn integration_scan_comprehensive_vulnerabilities() {
        // When run via `cargo test` from the workspace root the cwd is the workspace root;
        // when run directly from the crate directory the cwd is the crate root.
        let path = "core/src/contracts/comprehensive-vulnerabilities.sol";
        let path_alt = "src/contracts/comprehensive-vulnerabilities.sol";
        let path_used = if std::path::Path::new(path).exists() {
            path
        } else if std::path::Path::new(path_alt).exists() {
            path_alt
        } else {
            panic!(
                "comprehensive-vulnerabilities.sol not found; tried '{}' and '{}'",
                path, path_alt
            )
        };
        let registry = build_registry();
        let mut parser = new_solidity_parser().expect("parser");
        let outcome = scan_file_with(path_used, &registry, &mut parser);
        assert!(
            outcome.errors.is_empty(),
            "scan should succeed without errors"
        );
        let findings = &outcome.findings;
        assert!(
            findings.len() >= 5,
            "comprehensive-vulnerabilities.sol should yield >=5 findings (got {})",
            findings.len()
        );
        let types: std::collections::HashSet<_> = findings
            .iter()
            .map(|f| f.vulnerability_type.as_str())
            .collect();
        assert!(types.contains("Reentrancy"));
        assert!(types.contains("tx.origin Authentication"));

        for f in findings {
            assert!(!f.detector_id.is_empty(), "detector_id should be set");
            assert!(!f.id.is_empty(), "id should be computed");
        }
    }

    // ========== Exit code tests ==========

    #[test]
    fn exit_code_for_stats_maps_correctly() {
        use veil::scan::exit_code_for_stats;

        let clean = Statistics::default();
        assert_eq!(exit_code_for_stats(&clean), 0);

        let low_only = Statistics {
            low: 1,
            ..Default::default()
        };
        assert_eq!(exit_code_for_stats(&low_only), 1);

        let medium = Statistics {
            medium: 2,
            ..Default::default()
        };
        assert_eq!(exit_code_for_stats(&medium), 1);

        let high = Statistics {
            high: 1,
            medium: 3,
            ..Default::default()
        };
        assert_eq!(exit_code_for_stats(&high), 2);

        let critical = Statistics {
            critical: 1,
            high: 2,
            ..Default::default()
        };
        assert_eq!(exit_code_for_stats(&critical), 3);
    }

    // ========== Suppression tests ==========

    #[test]
    fn suppression_parse_veil_ignores() {
        let source = r#"
// veil-ignore: reentrancy
        (bool ok,) = msg.sender.call{value: 1}("");
// veil-ignore: tx.origin
        require(tx.origin == owner);
// veil-ignore: reentrancy L20
"#;
        let ignores = parse_veil_ignores(source);
        assert!(!ignores.is_empty());
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 2 && t.as_deref() == Some("reentrancy")));
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 3 && t.as_deref() == Some("reentrancy")));
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 5 && t.as_deref() == Some("tx.origin")));
        assert!(ignores
            .iter()
            .any(|(l, t)| *l == 20 && t.as_deref() == Some("reentrancy")));
    }

    #[test]
    fn suppression_inline_ignores_finding() {
        let source = r#"
pragma solidity ^0.8.0;
contract C {
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // veil-ignore: reentrancy
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"#;
        let findings = run_detector(&ReentrancyDetector, source);
        assert!(
            !findings.is_empty(),
            "reentrancy should be found without filter"
        );
        let filtered = filter_findings_by_inline_ignores(findings, source);
        assert!(
            filtered.is_empty(),
            "finding should be suppressed by // veil-ignore: reentrancy on line above"
        );
    }

    #[test]
    fn suppression_baseline_filters_known_findings() {
        let baseline_json = r#"{"findings":[{"id":"","detector_id":"","severity":"High","confidence":"High","line":5,"vulnerability_type":"Reentrancy","message":"","suggestion":"","file":"x.sol"}],"statistics":{"critical":0,"high":1,"medium":0,"low":0,"confidence_high":1,"confidence_medium":0,"confidence_low":0}}"#;
        let baseline: BaselineFile = serde_json::from_str(baseline_json).expect("parse");
        let set: HashSet<_> = baseline
            .findings
            .into_iter()
            .map(|f| {
                (
                    f.file.unwrap_or_default(),
                    f.line as usize,
                    normalize_vuln_type(&f.vulnerability_type),
                )
            })
            .collect();
        let finding = test_finding(
            Severity::High,
            Confidence::High,
            5,
            "Reentrancy",
            Some("x.sol"),
        );
        let findings = vec![finding];
        let filtered = filter_findings_by_baseline(findings, &set);
        assert!(
            filtered.is_empty(),
            "finding in baseline should be filtered out"
        );
    }
}
