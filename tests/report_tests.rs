//! Tests for NSE structured run reports.
//!
//! Covers: report construction, profile/sandbox/limits population, resolver
//! diagnostics mapping, library metadata, rule evaluation, output truncation,
//! compatibility computation, serialization roundtrip, and build_report integration.

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits};
use eggsec_nse::profile::ResolvedNseExecutionProfile;
use eggsec_nse::report::*;
use eggsec_nse::resolver::{NseLoadDiagnostic, NseScriptSource};
use eggsec_nse::{NseExecutor, SandboxConfig};

fn test_limits() -> NseExecutionLimits {
    NseExecutionLimits {
        wall_clock_timeout: Some(std::time::Duration::from_secs(5)),
        lua_instruction_budget: Some(100_000),
        max_output_bytes: Some(1024),
        max_script_bytes: Some(4096),
        max_required_module_bytes: Some(2048),
        max_network_operations: Some(50),
        max_filesystem_operations: Some(25),
        max_lua_memory_bytes: Some(1024 * 1024),
        ..NseExecutionLimits::default()
    }
}

#[test]
fn test_report_new_defaults() {
    let report = NseRunReport::new("192.168.1.1", "test-script");
    assert_eq!(report.target, "192.168.1.1");
    assert_eq!(report.script_name, "test-script");
    assert_eq!(report.script_source.kind, "unknown");
    assert_eq!(report.profile.kind, "unknown");
    assert!(!report.sandbox.enabled);
    assert!(report.warnings.is_empty());
    assert!(report.errors.is_empty());
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Unknown
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Unknown);
}

#[test]
fn test_report_with_manual_permissive_profile() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = NseRunReport::new("10.0.0.1", "ssl-cert").with_profile(&profile);

    assert_eq!(report.profile.kind, "manual-permissive");
    assert!(!report.profile.warnings.is_empty());
    assert!(report.profile.audit_label.contains("manual"));
    assert!(!report.sandbox.enabled || report.sandbox.feature_compiled);
    assert!(report.limits.wall_clock_timeout_secs.is_some());
    assert!(report.limits.lua_instruction_budget.is_some());
}

#[test]
fn test_report_with_agent_safe_profile() {
    let cidrs: Vec<ipnetwork::IpNetwork> = vec!["192.168.1.0/24".parse().unwrap()];
    let profile = ResolvedNseExecutionProfile::agent_safe("192.168.1.1", &cidrs);
    let report = NseRunReport::new("192.168.1.1", "http-enum").with_profile(&profile);

    assert_eq!(report.profile.kind, "agent-safe");
    assert!(report.limits.wall_clock_timeout_secs.is_some());
    let timeout = report.limits.wall_clock_timeout_secs.unwrap();
    assert!(
        timeout <= 16.0,
        "agent-safe timeout should be <= 15s, got {}",
        timeout
    );
}

#[test]
fn test_report_with_ci_safe_profile() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    let report = NseRunReport::new("10.0.0.1", "fingerprint").with_profile(&profile);

    assert_eq!(report.profile.kind, "ci-safe");
    assert!(report.sandbox.enabled || !report.sandbox.feature_compiled);
}

#[test]
fn test_report_with_script_source_builtin() {
    let source = NseScriptSource::Builtin {
        name: "ssl-cert".to_string(),
    };
    let report = NseRunReport::new("10.0.0.1", "ssl-cert").with_script_source(&source);

    assert_eq!(report.script_source.kind, "builtin");
    assert_eq!(report.script_source.label, "ssl-cert");
    assert_eq!(report.script_source.size, 0);
}

#[test]
fn test_report_with_script_source_file() {
    let source = NseScriptSource::File {
        path: std::path::PathBuf::from("/tmp/test.lua"),
    };
    let report = NseRunReport::new("10.0.0.1", "test").with_script_source(&source);

    assert_eq!(report.script_source.kind, "file");
    assert!(report.script_source.label.contains("test.lua"));
}

#[test]
fn test_report_with_script_source_inline() {
    let source = NseScriptSource::InlineManual {
        label: "my-script".to_string(),
        content: "return 'hello'".to_string(),
    };
    let report = NseRunReport::new("10.0.0.1", "my-script").with_script_source(&source);

    assert_eq!(report.script_source.kind, "inline");
    assert_eq!(report.script_source.label, "my-script");
    assert_eq!(report.script_source.size, 14);
}

#[test]
fn test_report_with_stats() {
    let limits = test_limits();
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
        eggsec_nse::default_script_policy(),
        eggsec_nse::default_module_policy(),
    )
    .unwrap();

    let _ = executor.run_script_with_limits("return 1 + 1");
    let stats = executor.execution_stats();

    let report = NseRunReport::new("10.0.0.1", "test").with_stats(&stats);

    assert!(report.stats.elapsed_secs >= 0.0);
    assert!(report.stats.lua_instruction_count > 0);
}

#[test]
fn test_report_with_resolver_diagnostics_resolved() {
    let diagnostics = vec![NseLoadDiagnostic::Resolved {
        source: NseScriptSource::Builtin {
            name: "ssl-cert".to_string(),
        },
        bytes: 1024,
    }];

    let report = NseRunReport::new("10.0.0.1", "ssl-cert").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.total_diagnostics, 1);
    assert_eq!(report.resolver.resolved_count, 1);
    assert_eq!(report.resolver.blocked_count, 0);
    assert_eq!(report.resolver.rejected_count, 0);
    assert_eq!(report.resolver.diagnostics[0].kind, "resolved");
    assert!(report.resolver.diagnostics[0].detail.contains("1024"));
}

#[test]
fn test_report_with_resolver_diagnostics_blocked() {
    let diagnostics = vec![NseLoadDiagnostic::Blocked {
        source: NseScriptSource::File {
            path: std::path::PathBuf::from("/tmp/evil.lua"),
        },
        reason: "script files not allowed by profile".to_string(),
    }];

    let report = NseRunReport::new("10.0.0.1", "evil").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.blocked_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "blocked");
    assert!(report.resolver.diagnostics[0]
        .detail
        .contains("not allowed"));
}

#[test]
fn test_report_with_resolver_diagnostics_outside_root() {
    let diagnostics = vec![NseLoadDiagnostic::OutsideRoot {
        path: std::path::PathBuf::from("/etc/passwd"),
        root: std::path::PathBuf::from("/opt/nse"),
    }];

    let report = NseRunReport::new("10.0.0.1", "test").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.rejected_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "outside_root");
    assert!(report.resolver.diagnostics[0].detail.contains("/opt/nse"));
}

#[test]
fn test_report_with_resolver_diagnostics_symlink_rejected() {
    let diagnostics = vec![NseLoadDiagnostic::SymlinkRejected {
        path: std::path::PathBuf::from("/tmp/link.lua"),
        resolved: std::path::PathBuf::from("/etc/shadow"),
    }];

    let report = NseRunReport::new("10.0.0.1", "test").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.rejected_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "symlink_rejected");
    assert!(report.resolver.diagnostics[0]
        .detail
        .contains("/etc/shadow"));
}

#[test]
fn test_report_with_resolver_diagnostics_module_name_rejected() {
    let diagnostics = vec![NseLoadDiagnostic::ModuleNameRejected {
        name: "../escape".to_string(),
        reason: "name contains path separator".to_string(),
    }];

    let report = NseRunReport::new("10.0.0.1", "test").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.rejected_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "module_name_rejected");
}

#[test]
fn test_report_with_resolver_diagnostics_oversized() {
    let diagnostics = vec![NseLoadDiagnostic::OversizedRejected {
        source: NseScriptSource::File {
            path: std::path::PathBuf::from("/tmp/big.lua"),
        },
        size: 100_000,
        limit: 50_000,
    }];

    let report = NseRunReport::new("10.0.0.1", "big").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.rejected_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "oversized_rejected");
    assert!(report.resolver.diagnostics[0].detail.contains("100000"));
}

#[test]
fn test_report_with_resolver_diagnostics_module_load_failed() {
    let diagnostics = vec![NseLoadDiagnostic::ModuleLoadFailed {
        name: "bad_module".to_string(),
        path: std::path::PathBuf::from("/tmp/bad_module.lua"),
        error: "syntax error".to_string(),
    }];

    let report = NseRunReport::new("10.0.0.1", "test").with_resolver_diagnostics(&diagnostics);

    assert_eq!(report.resolver.rejected_count, 1);
    assert_eq!(report.resolver.diagnostics[0].kind, "module_load_failed");
    assert!(report.resolver.diagnostics[0]
        .detail
        .contains("syntax error"));
}

#[test]
fn test_report_with_output() {
    let report = NseRunReport::new("10.0.0.1", "test").with_output("line1\nline2\nline3");

    assert!(report.output.has_output);
    assert_eq!(report.output.line_count, 3);
    assert!(!report.output.truncated);
    assert_eq!(report.output.content, "line1\nline2\nline3");
}

#[test]
fn test_report_with_empty_output() {
    let report = NseRunReport::new("10.0.0.1", "test").with_output("");

    assert!(!report.output.has_output);
    assert_eq!(report.output.line_count, 0);
}

#[test]
fn test_report_output_truncation() {
    let large_output = "x".repeat(15000);
    let report = NseRunReport::new("10.0.0.1", "test").with_output(&large_output);

    assert!(report.output.truncated);
    assert!(report.output.content.len() < 15000);
    assert!(report.output.content.contains("truncated"));
}

#[test]
fn test_report_with_error() {
    let report = NseRunReport::new("10.0.0.1", "test").with_error("script execution failed");

    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0], "script execution failed");
}

#[test]
fn test_compatibility_compatible() {
    let report = NseRunReport::new("10.0.0.1", "test").compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Compatible
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert!(report.compatibility.unsupported_features.is_empty());
    assert!(report.compatibility.approximations.is_empty());
}

#[test]
fn test_compatibility_with_warnings() {
    let report = NseRunReport::new("10.0.0.1", "test")
        .with_error("non-fatal issue")
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
}

#[test]
fn test_compatibility_partial_from_rejections() {
    let diagnostics = vec![NseLoadDiagnostic::ModuleNameRejected {
        name: "bad".to_string(),
        reason: "test".to_string(),
    }];

    let report = NseRunReport::new("10.0.0.1", "test")
        .with_resolver_diagnostics(&diagnostics)
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Minimal);
    assert!(!report.compatibility.unsupported_features.is_empty());
}

#[test]
fn test_compatibility_with_approximations() {
    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: true,
        exactness: "approximate".to_string(),
        error: None,
        summary: "port state approximated".to_string(),
        unsupported: None,
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }];

    let report = NseRunReport::new("10.0.0.1", "test")
        .with_rules(rules)
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Approximate);
    assert!(!report.compatibility.approximations.is_empty());
}

#[test]
fn test_compatibility_combined_errors_and_rejections() {
    let diagnostics = vec![NseLoadDiagnostic::ModuleNameRejected {
        name: "x".to_string(),
        reason: "test".to_string(),
    }];

    let report = NseRunReport::new("10.0.0.1", "test")
        .with_resolver_diagnostics(&diagnostics)
        .with_error("fatal error")
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
}

#[test]
fn test_report_serialization_roundtrip() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let diagnostics = vec![NseLoadDiagnostic::Resolved {
        source: NseScriptSource::Builtin {
            name: "ssl-cert".to_string(),
        },
        bytes: 512,
    }];

    let report = NseRunReport::new("10.0.0.1", "ssl-cert")
        .with_profile(&profile)
        .with_script_source(&NseScriptSource::Builtin {
            name: "ssl-cert".to_string(),
        })
        .with_resolver_diagnostics(&diagnostics)
        .with_output("test output")
        .with_error("minor issue")
        .compute_compatibility();

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: NseRunReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.target, report.target);
    assert_eq!(deserialized.script_name, report.script_name);
    assert_eq!(deserialized.profile.kind, report.profile.kind);
    assert_eq!(
        deserialized.compatibility.status,
        report.compatibility.status
    );
    assert_eq!(
        deserialized.compatibility.fidelity,
        report.compatibility.fidelity
    );
    assert_eq!(deserialized.errors, report.errors);
    assert_eq!(
        deserialized.resolver.total_diagnostics,
        report.resolver.total_diagnostics
    );
}

#[test]
fn test_report_json_pretty_print() {
    let report = NseRunReport::new("10.0.0.1", "test").with_error("test error");

    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(json.contains("\"target\""));
    assert!(json.contains("\"10.0.0.1\""));
    assert!(json.contains("\"errors\""));
    assert!(json.contains("test error"));
}

#[test]
fn test_limits_summary_from_execution_limits() {
    let limits = test_limits();
    let summary = NseLimitsSummary::from(&limits);

    assert!(summary.wall_clock_timeout_secs.is_some());
    assert!(summary.lua_instruction_budget.is_some());
    assert!(summary.max_output_bytes.is_some());
    assert!(summary.max_script_bytes.is_some());
    assert!(summary.max_required_module_bytes.is_some());
    assert!(summary.max_network_operations.is_some());
    assert!(summary.max_filesystem_operations.is_some());
    assert!(summary.max_lua_memory_bytes.is_some());

    let timeout = summary.wall_clock_timeout_secs.unwrap();
    assert!(
        (4.9..5.1).contains(&timeout),
        "expected ~5.0, got {}",
        timeout
    );
}

#[test]
fn test_limits_summary_unlimited() {
    let limits = NseExecutionLimits::unlimited();
    let summary = NseLimitsSummary::from(&limits);

    assert!(summary.wall_clock_timeout_secs.is_none());
    assert!(summary.lua_instruction_budget.is_none());
    assert!(summary.max_output_bytes.is_none());
}

#[test]
fn test_rule_evaluation_report_fields() {
    let rule = NseRuleEvaluationReport {
        kind: "hostrule".to_string(),
        evaluated: true,
        matched: false,
        exactness: "exact".to_string(),
        error: None,
        summary: "host not matched".to_string(),
        unsupported: None,
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    };

    let report = NseRunReport::new("10.0.0.1", "test")
        .with_rules(vec![rule])
        .compute_compatibility();

    assert_eq!(report.rules.len(), 1);
    assert_eq!(report.rules[0].kind, "hostrule");
    assert!(!report.rules[0].matched);
    assert_eq!(report.rules[0].exactness, "exact");
}

#[test]
fn test_library_use_report_fields() {
    let lib = NseLibraryUseReport {
        name: "stdnse".to_string(),
        category: "Core".to_string(),
        registered: true,
        side_effects: vec![],
        fallback_behavior: "hard-fail".to_string(),
        notes: "Standard NSE library".to_string(),
        loaded: true,
        warnings: vec![],
    };

    let report = NseRunReport::new("10.0.0.1", "test").with_libraries(vec![lib]);

    assert_eq!(report.libraries.len(), 1);
    assert!(report.libraries[0].registered);
    assert!(report.libraries[0].loaded);
}

#[test]
fn test_build_report_integration() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let limits = test_limits();
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
        profile.script_policy.clone(),
        profile.module_policy.clone(),
    )
    .unwrap();

    let _ = executor.run_script_with_limits("return 42");
    let stats = executor.execution_stats();
    let source = NseScriptSource::Builtin {
        name: "test-script".to_string(),
    };

    let report = NseRunReport::new("10.0.0.1", "test-script")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_stats(&stats)
        .with_output("42")
        .compute_compatibility();

    assert_eq!(report.target, "10.0.0.1");
    assert_eq!(report.profile.kind, "manual-permissive");
    assert_eq!(report.script_source.kind, "builtin");
    assert!(report.stats.elapsed_secs >= 0.0);
    assert!(report.output.has_output);
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
}

#[test]
fn test_build_report_via_executor_method() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let limits = test_limits();
    let mut executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
        profile.script_policy.clone(),
        profile.module_policy.clone(),
    )
    .unwrap();

    let _ = executor.set_target("10.0.0.1");
    let _ = executor.run_script_with_limits("return 'hello'");

    let source = NseScriptSource::Builtin {
        name: "test".to_string(),
    };
    let diagnostics = vec![];

    let report = executor.build_report(&profile, &source, "hello", &diagnostics);

    assert_eq!(report.target, "10.0.0.1");
    assert_eq!(report.script_name, "test");
    assert!(report.stats.elapsed_secs >= 0.0);
    assert!(report.output.has_output);
    assert_eq!(report.output.content, "hello");
    assert!(report.libraries.is_empty());
}

#[test]
fn test_capability_events_serialization_roundtrip() {
    use eggsec_nse::capabilities::{NseCapabilityEvent, NseCapabilityKind};

    let events = vec![
        NseCapabilityEvent {
            kind: NseCapabilityKind::FilesystemRead,
            operation: "io.open".to_string(),
            target: Some("/tmp/test.txt".to_string()),
            allowed: true,
            reason: None,
            bytes: Some(1024),
        },
        NseCapabilityEvent {
            kind: NseCapabilityKind::ProcessExec,
            operation: "io.popen".to_string(),
            target: Some("id".to_string()),
            allowed: false,
            reason: Some("AgentSafe denies process execution".to_string()),
            bytes: None,
        },
        NseCapabilityEvent {
            kind: NseCapabilityKind::NetworkTcp,
            operation: "socket.connect".to_string(),
            target: Some("10.0.0.1:80".to_string()),
            allowed: true,
            reason: Some("network connection allowed with warning".to_string()),
            bytes: None,
        },
    ];

    let report = NseRunReport::new("10.0.0.1", "test-script")
        .with_capability_events(events)
        .compute_compatibility();

    assert_eq!(report.capability_events.len(), 3);
    assert_eq!(report.capability_events[0].kind, "filesystem_read");
    assert!(report.capability_events[0].allowed);
    assert_eq!(report.capability_events[1].kind, "process_exec");
    assert!(!report.capability_events[1].allowed);
    assert!(report.capability_events[1]
        .reason
        .as_ref()
        .unwrap()
        .contains("denies"));
    assert_eq!(report.capability_events[2].kind, "network_tcp");
    assert!(report.capability_events[2].allowed);

    // Capability denials should affect compatibility status
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial
    );

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: NseRunReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.capability_events.len(), 3);
    assert_eq!(
        deserialized.capability_events[0].kind,
        report.capability_events[0].kind
    );
    assert_eq!(
        deserialized.capability_events[0].operation,
        report.capability_events[0].operation
    );
    assert_eq!(
        deserialized.capability_events[0].target,
        report.capability_events[0].target
    );
    assert_eq!(
        deserialized.capability_events[0].allowed,
        report.capability_events[0].allowed
    );
    assert_eq!(
        deserialized.capability_events[0].reason,
        report.capability_events[0].reason
    );
    assert_eq!(
        deserialized.capability_events[1].kind,
        report.capability_events[1].kind
    );
    assert_eq!(
        deserialized.capability_events[1].allowed,
        report.capability_events[1].allowed
    );
    assert_eq!(
        deserialized.capability_events[2].kind,
        report.capability_events[2].kind
    );
    assert_eq!(
        deserialized.compatibility.status,
        NseRunCompatibilityStatus::Partial
    );
}
