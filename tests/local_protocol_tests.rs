//! NSE local protocol fixture tests.
//!
//! Starts real local TCP/HTTP/UDP servers and executes NSE scripts against
//! them. Unlike the corpus harness (which tests mock/denial-only paths),
//! these tests verify that NSE scripts produce correct runtime reports when
//! connecting to actual local services.
//!
//! Run with:
//!   cargo test -p eggsec-nse --features nse --test local_protocol_tests

#![cfg(feature = "nse")]

mod local_fixtures;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use eggsec_nse::limits::NseExecutionLimits;
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    ResolvedNseExecutionProfile,
};
use eggsec_nse::report::{extract_evidence, NseRunReport};
use eggsec_nse::resolver::{NseScriptSource, ScriptResolver};
use eggsec_nse::NseExecutor;

/// Monotonically increasing counter for unique temp dirs across concurrent tests.
static INVOCATION_COUNTER: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nse_corpus")
}

fn read_fixture(path: &str) -> String {
    let full = corpus_dir().join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read fixture {:?}: {}", full, e))
}

fn test_limits() -> NseExecutionLimits {
    NseExecutionLimits {
        wall_clock_timeout: Some(std::time::Duration::from_secs(10)),
        lua_instruction_budget: Some(200_000),
        max_output_bytes: Some(1024 * 1024),
        max_script_bytes: Some(65536),
        max_required_module_bytes: Some(32768),
        max_network_operations: Some(50),
        max_filesystem_operations: Some(25),
        max_lua_memory_bytes: Some(8 * 1024 * 1024),
        ..NseExecutionLimits::default()
    }
}

fn make_script_policy(roots: Vec<PathBuf>) -> NseScriptPolicy {
    NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: true,
        allowed_script_roots: roots,
        allow_conventional_nmap_paths: false,
        max_script_bytes: Some(65536),
    }
}

fn make_module_policy(roots: Vec<PathBuf>) -> NseModulePolicy {
    NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: true,
        allowed_module_roots: roots,
        max_module_bytes: Some(32768),
    }
}

fn make_manual_permissive_profile(roots: Vec<PathBuf>) -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile {
        kind: NseExecutionProfileKind::ManualPermissive,
        sandbox: eggsec_nse::SandboxConfig::default(),
        limits: test_limits(),
        script_policy: make_script_policy(roots.clone()),
        module_policy: make_module_policy(roots),
        network_policy: NseNetworkPolicy::AllowAllManual,
        audit_label: "nse:local-protocol:manual-permissive".to_string(),
        warnings: vec![],
    }
}

fn make_agent_safe_runtime_profile(roots: Vec<PathBuf>) -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile {
        kind: NseExecutionProfileKind::AgentSafe,
        sandbox: eggsec_nse::SandboxConfig {
            enabled: false,
            allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
            ..Default::default()
        },
        limits: test_limits(),
        script_policy: make_script_policy(roots.clone()),
        module_policy: make_module_policy(roots),
        network_policy: NseNetworkPolicy::DenyAll,
        audit_label: "nse:local-protocol:agent-safe-runtime".to_string(),
        warnings: vec![],
    }
}

fn make_ci_safe_runtime_profile(roots: Vec<PathBuf>) -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile {
        kind: NseExecutionProfileKind::CiSafe,
        sandbox: eggsec_nse::SandboxConfig::default(),
        limits: test_limits(),
        script_policy: make_script_policy(roots.clone()),
        module_policy: make_module_policy(roots),
        network_policy: NseNetworkPolicy::DenyAll,
        audit_label: "nse:local-protocol:ci-safe-runtime".to_string(),
        warnings: vec![],
    }
}

/// Execute a fixture script against a local server and return the report.
fn run_local_fixture(
    script_path: &str,
    target_ip: &str,
    port: u16,
    protocol: &str,
    state: &str,
    service: Option<&str>,
    profile: &ResolvedNseExecutionProfile,
) -> (NseRunReport, Vec<eggsec_nse::report::NseEvidenceItem>) {
    let invocation_id = INVOCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!(
        "eggsec-nse-local-proto-{}-{}",
        std::process::id(),
        invocation_id,
    ));
    let _ = std::fs::create_dir_all(&tmp);

    let content = read_fixture(script_path);
    let script_name = script_path.rsplit('/').next().unwrap_or("script.nse");
    let fixture_path = tmp.join(script_name);
    std::fs::write(&fixture_path, &content).expect("write fixture");

    let mut executor =
        NseExecutor::with_profile(profile).expect("with_profile should construct executor");

    executor
        .set_target(target_ip)
        .expect("set_target should succeed");

    executor
        .add_port(port, protocol, state, service.map(|s| s.to_string()))
        .expect("add_port should succeed");

    let mut resolver = ScriptResolver::new(
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.limits.clone(),
    );
    let source = NseScriptSource::File {
        path: fixture_path.clone(),
    };

    let script_content = match resolver.resolve_script(source.clone()) {
        Ok(resolved) => resolved.content,
        Err(err) => {
            let diagnostics = resolver.take_diagnostics();
            let report = NseRunReport::new(target_ip, script_name)
                .with_profile(profile)
                .with_script_source(&source)
                .with_resolver_diagnostics(&diagnostics)
                .with_error(&format!("{}", err))
                .compute_compatibility();
            let evidence = extract_evidence(
                &report.target,
                &report.script_name,
                &report.capability_events,
                &report.compatibility,
                &report.rules,
                &report.output,
            );
            return (report.with_evidence(evidence.clone()), evidence);
        }
    };

    let diagnostics = resolver.take_diagnostics();

    let (output, _raw, rule_reports) = match executor.run_script_with_rules(&script_content) {
        Ok(result) => result,
        Err(err) => (
            format!("execution error: {}", err),
            vec![],
            vec![eggsec_nse::report::NseRuleEvaluationReport {
                kind: "execution".to_string(),
                evaluated: false,
                matched: false,
                exactness: "exact".to_string(),
                error: Some(err.to_string()),
                summary: format!("execution failed: {}", err),
                unsupported: None,
                host_context_source: None,
                port_context_source: None,
                service_context_available: None,
                fidelity_reason: None,
            }],
        ),
    };

    let library_reports = executor.library_reports();
    let capability_events = executor.capability_events();

    let mut report = NseRunReport::new(target_ip, script_name)
        .with_profile(profile)
        .with_script_source(&source)
        .with_stats(&executor.execution_stats())
        .with_resolver_diagnostics(&diagnostics)
        .with_rules(rule_reports)
        .with_libraries(library_reports)
        .with_capability_events(capability_events)
        .with_output(&output);

    for rule in report.rules.clone() {
        if let Some(err) = &rule.error {
            let label = format!("rule {}: {}", rule.kind, err);
            report = report.with_error(&label);
        }
    }

    let report = report.compute_compatibility();
    let evidence = extract_evidence(
        &report.target,
        &report.script_name,
        &report.capability_events,
        &report.compatibility,
        &report.rules,
        &report.output,
    );
    (report.with_evidence(evidence.clone()), evidence)
}

// ---------------------------------------------------------------------------
// Tests: TCP Local Protocol
// ---------------------------------------------------------------------------

/// TCP connect + echo against a local TCP echo server.
#[test]
fn local_tcp_connect_echo_success() {
    let server = local_fixtures::TcpEchoServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/tcp_connect_echo.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        None,
        &profile,
    );

    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "TCP echo fixture should be compatible (possibly with warnings): status={:?}, output={}, errors={:?}",
        report.compatibility.status,
        report.output.content,
        report.errors,
    );
    assert!(
        report.output.content.contains("ECHO: hello from nse"),
        "output should contain echo response: {}",
        report.output.content,
    );
    // Verify TCP capability events were recorded
    let tcp_events: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp")
        .collect();
    assert!(
        !tcp_events.is_empty(),
        "should have network_tcp capability events"
    );
}

/// TCP connect denied under AgentSafe profile.
#[test]
fn local_tcp_connect_denied_agent_safe() {
    let server = local_fixtures::TcpEchoServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/tcp_connect_denied.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        None,
        &profile,
    );

    // Under AgentSafe with DenyAll network, TCP connect should be denied
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe should deny TCP: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
}

/// TCP connect denied under CiSafe profile.
#[test]
fn local_tcp_connect_denied_ci_safe() {
    let server = local_fixtures::TcpEchoServer::start();
    let profile = make_ci_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/tcp_connect_denied.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        None,
        &profile,
    );

    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "CiSafe should deny TCP: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
}

// ---------------------------------------------------------------------------
// Tests: HTTP Local Protocol
// ---------------------------------------------------------------------------

/// HTTP GET against local HTTP server — extracts title.
#[test]
fn local_http_get_title_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    assert!(
        report.output.content.contains("title: Eggsec Test Page"),
        "output should contain extracted title: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP GET should be compatible (possibly with warnings): status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    // ManualPermissive must actually reach the server
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP GET must reach the server"
    );
}

/// HTTP POST against local HTTP server.
#[test]
fn local_http_post_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_post_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    assert!(
        report.output.content.contains("POST status=200"),
        "output should contain POST status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP POST should be compatible (possibly with warnings): status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    // ManualPermissive must actually reach the server
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP POST must reach the server"
    );
}

/// HTTP PUT against local HTTP server.
#[test]
fn local_http_put_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_put_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    assert!(
        report.output.content.contains("PUT status=200"),
        "output should contain PUT status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP PUT should be compatible: status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP PUT must reach the server"
    );
}

/// HTTP DELETE against local HTTP server.
#[test]
fn local_http_delete_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_delete_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    assert!(
        report.output.content.contains("DELETE status=200"),
        "output should contain DELETE status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP DELETE should be compatible: status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP DELETE must reach the server"
    );
}

/// HTTP HEAD against local HTTP server.
#[test]
fn local_http_head_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_head_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    assert!(
        report.output.content.contains("HEAD status=200"),
        "output should contain HEAD status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP HEAD should be compatible: status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP HEAD must reach the server"
    );
}

/// HTTP OPTIONS against local HTTP server.
#[test]
fn local_http_options_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_options_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    assert!(
        report.output.content.contains("OPTIONS status=200"),
        "output should contain OPTIONS status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP OPTIONS should be compatible: status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP OPTIONS must reach the server"
    );
}

/// Generic HTTP request (GET) against local HTTP server.
#[test]
fn local_http_request_success() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_request_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    assert!(
        report.output.content.contains("REQUEST status=200"),
        "output should contain REQUEST status: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "HTTP request should be compatible: status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
    assert!(
        server.hits() > 0,
        "ManualPermissive HTTP request must reach the server"
    );
}

/// HTTP POST under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_post_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_post_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP POST must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP POST must not reach the server"
    );
}

/// HTTP POST under CiSafe: network TCP denied, zero hits.
#[test]
fn local_http_post_ci_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_ci_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_post_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "CiSafe HTTP POST must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "CiSafe HTTP POST must not reach the server"
    );
}

/// HTTP PUT under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_put_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_put_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP PUT must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP PUT must not reach the server"
    );
}

/// HTTP DELETE under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_delete_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_delete_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP DELETE must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP DELETE must not reach the server"
    );
}

/// HTTP HEAD under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_head_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_head_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP HEAD must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP HEAD must not reach the server"
    );
}

/// HTTP OPTIONS under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_options_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_options_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP OPTIONS must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP OPTIONS must not reach the server"
    );
}

/// Generic HTTP request under AgentSafe: network TCP denied, zero hits.
#[test]
fn local_http_request_agent_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_request_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP request must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP request must not reach the server"
    );
}

/// HTTP GET under AgentSafe: capability context denies network TCP, so reqwest
/// is never reached and the server receives zero hits.
#[test]
fn local_http_get_agent_safe_documentation() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    // Script should complete without crashing
    assert!(
        report.output.content.contains("HTTP GET failed")
            || report.output.content.contains("title:")
            || report.output.content.is_empty(),
        "AgentSafe HTTP GET should complete without crash: {}",
        report.output.content,
    );

    // Must have at least one network_tcp denial event
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "AgentSafe HTTP GET must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );

    // Server must not have been contacted
    assert_eq!(
        server.hits(),
        0,
        "AgentSafe HTTP GET must not reach the server"
    );
}

/// HTTP GET under CiSafe: capability context denies network TCP, so reqwest
/// is never reached and the server receives zero hits.
#[test]
fn local_http_get_ci_safe_denied() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_ci_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    // Script should complete without crashing
    assert!(
        report.output.content.contains("HTTP GET failed")
            || report.output.content.contains("title:")
            || report.output.content.is_empty(),
        "CiSafe HTTP GET should complete without crash: {}",
        report.output.content,
    );

    // Must have at least one network_tcp denial event
    let tcp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_tcp" && !e.allowed)
        .collect();
    assert!(
        !tcp_denials.is_empty(),
        "CiSafe HTTP GET must produce network_tcp denial events: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );

    // Server must not have been contacted
    assert_eq!(
        server.hits(),
        0,
        "CiSafe HTTP GET must not reach the server"
    );
}

// ---------------------------------------------------------------------------
// Tests: UDP Local Protocol
// ---------------------------------------------------------------------------

/// UDP echo against local UDP server.
#[test]
fn local_udp_echo_success() {
    let server = local_fixtures::UdpEchoServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/udp_echo.nse",
        "127.0.0.1",
        server.port(),
        "udp",
        "open",
        None,
        &profile,
    );

    assert!(
        report.output.content.contains("udp echo: udp-test"),
        "output should contain UDP echo response: {}",
        report.output.content,
    );
    assert!(
        matches!(
            report.compatibility.status,
            eggsec_nse::report::NseRunCompatibilityStatus::Compatible
                | eggsec_nse::report::NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "UDP echo should be compatible (possibly with warnings): status={:?}, errors={:?}",
        report.compatibility.status,
        report.errors,
    );
}

/// UDP denied under AgentSafe profile.
#[test]
fn local_udp_denied_agent_safe() {
    let server = local_fixtures::UdpEchoServer::start();
    let profile = make_agent_safe_runtime_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/udp_echo.nse",
        "127.0.0.1",
        server.port(),
        "udp",
        "open",
        None,
        &profile,
    );

    let udp_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "network_udp" && !e.allowed)
        .collect();
    assert!(
        !udp_denials.is_empty(),
        "AgentSafe should deny UDP: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
}

// ---------------------------------------------------------------------------
// Tests: DNS Denial (no real DNS server needed — resolver injection not yet available)
// ---------------------------------------------------------------------------

/// DNS query denied under AgentSafe profile.
/// Uses the existing dns_lookup_mock.nse which calls dns.query("example.com").
/// Requires a tokio runtime because the DNS library calls Handle::current().
#[test]
fn local_dns_denied_agent_safe() {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let _guard = rt.enter();

    let profile = make_agent_safe_runtime_profile(vec![]);
    let invocation_id = INVOCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!(
        "eggsec-nse-local-dns-{}-{}",
        std::process::id(),
        invocation_id,
    ));
    let _ = std::fs::create_dir_all(&tmp);

    let content = read_fixture("scripts/protocol/dns_lookup_mock.nse");
    let fixture_path = tmp.join("dns_lookup_mock.nse");
    std::fs::write(&fixture_path, &content).expect("write fixture");

    let mut executor =
        NseExecutor::with_profile(&profile).expect("with_profile should construct executor");
    executor.set_target("127.0.0.1").expect("set_target");
    // Add a dummy port so portrule fires
    executor
        .add_port(80, "tcp", "open", None)
        .expect("add_port");

    let mut resolver = ScriptResolver::new(
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.limits.clone(),
    );
    let source = NseScriptSource::File {
        path: fixture_path.clone(),
    };
    let script_content = resolver.resolve_script(source.clone()).unwrap().content;
    let diagnostics = resolver.take_diagnostics();

    let (output, _raw, rule_reports) = executor
        .run_script_with_rules(&script_content)
        .unwrap_or_else(|err| {
            (
                format!("execution error: {}", err),
                vec![],
                vec![eggsec_nse::report::NseRuleEvaluationReport {
                    kind: "execution".to_string(),
                    evaluated: false,
                    matched: false,
                    exactness: "exact".to_string(),
                    error: Some(err.to_string()),
                    summary: format!("execution failed: {}", err),
                    unsupported: None,
                    host_context_source: None,
                    port_context_source: None,
                    service_context_available: None,
                    fidelity_reason: None,
                }],
            )
        });

    let capability_events = executor.capability_events();
    let report = NseRunReport::new("127.0.0.1", "dns_lookup_mock.nse")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_stats(&executor.execution_stats())
        .with_resolver_diagnostics(&diagnostics)
        .with_rules(rule_reports)
        .with_capability_events(capability_events)
        .with_output(&output)
        .compute_compatibility();

    let dns_denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| e.kind == "dns_resolution" && !e.allowed)
        .collect();
    assert!(
        !dns_denials.is_empty(),
        "AgentSafe should deny DNS: events={:?}, output={}",
        report.capability_events,
        report.output.content,
    );
}

// NOTE: TLS local protocol test deferred — the NSE socket library does raw
// TCP, not TLS. TLS testing requires the sslcert library's TlsConnector path.
// See Milestone 5 Phase 03 plan.

// ---------------------------------------------------------------------------
// Tests: Report Integrity
// ---------------------------------------------------------------------------

/// Verify that local protocol reports produce valid JSON round-trips.
#[test]
fn local_protocol_report_json_roundtrip() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    let json = serde_json::to_string(&report).expect("report serializes to JSON");
    let de: NseRunReport = serde_json::from_str(&json).expect("report deserializes from JSON");
    assert_eq!(
        de.compatibility.status, report.compatibility.status,
        "JSON round-trip status mismatch"
    );
    assert_eq!(
        de.compatibility.fidelity, report.compatibility.fidelity,
        "JSON round-trip fidelity mismatch"
    );
}

/// Verify that local protocol reports produce valid ReportEnvelopes.
#[test]
fn local_protocol_report_to_envelope_bridge() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, _evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    let envelope = eggsec_nse::bridge::to_report_envelope(&report);
    assert_eq!(envelope.domain_id.as_deref(), Some("nse"));
    assert!(
        !envelope.findings.is_empty(),
        "envelope should have findings for HTTP GET"
    );
}

/// Verify that local protocol evidence is correctly extracted.
#[test]
fn local_protocol_evidence_extraction() {
    let server = local_fixtures::HttpServer::start();
    let profile = make_manual_permissive_profile(vec![]);
    let (report, evidence) = run_local_fixture(
        "scripts/protocol/http_get_local.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        Some("http"),
        &profile,
    );

    // Script output should produce ScriptOutput evidence
    let has_script_output = evidence
        .iter()
        .any(|e| e.kind == eggsec_nse::report::NseEvidenceKind::ScriptOutput);
    assert!(
        has_script_output || report.output.content.is_empty(),
        "HTTP GET should produce ScriptOutput evidence"
    );
}

// ---------------------------------------------------------------------------
// Tests: Profile Comparison
// ---------------------------------------------------------------------------

/// Same script, different profiles: verify ManualPermissive allows, AgentSafe denies.
#[test]
fn local_protocol_profile_comparison_tcp() {
    let server = local_fixtures::TcpEchoServer::start();

    // ManualPermissive: should succeed
    let permissive = make_manual_permissive_profile(vec![]);
    let (report_ok, _) = run_local_fixture(
        "scripts/protocol/tcp_connect_echo.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        None,
        &permissive,
    );

    // AgentSafe: should deny
    let agent_safe = make_agent_safe_runtime_profile(vec![]);
    let (report_denied, _) = run_local_fixture(
        "scripts/protocol/tcp_connect_echo.nse",
        "127.0.0.1",
        server.port(),
        "tcp",
        "open",
        None,
        &agent_safe,
    );

    // Verify the contrast
    let permissive_tcp_ok = report_ok
        .capability_events
        .iter()
        .any(|e| e.kind == "network_tcp" && e.allowed);
    let agent_tcp_denied = report_denied
        .capability_events
        .iter()
        .any(|e| e.kind == "network_tcp" && !e.allowed);

    assert!(
        permissive_tcp_ok || report_ok.output.content.contains("ECHO:"),
        "ManualPermissive should allow TCP: output={}, events={:?}",
        report_ok.output.content,
        report_ok.capability_events,
    );
    assert!(
        agent_tcp_denied,
        "AgentSafe should deny TCP: events={:?}, output={}",
        report_denied.capability_events, report_denied.output.content,
    );
}
