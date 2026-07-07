#![cfg(feature = "nse")]

use eggsec_nse::format::format_human_report;
use eggsec_nse::report::*;

fn minimal_report(target: &str, script: &str) -> NseRunReport {
    NseRunReport::new(target, script)
}

#[test]
fn format_includes_header_and_metadata() {
    let report = minimal_report("10.0.0.1", "ssl-cert");
    let output = format_human_report(&report);
    assert!(output.contains("NSE Script Report"));
    assert!(output.contains("Target:"));
    assert!(output.contains("10.0.0.1"));
    assert!(output.contains("Script:"));
    assert!(output.contains("ssl-cert"));
    assert!(output.contains("Profile:"));
    assert!(output.contains("Elapsed:"));
}

#[test]
fn format_compatibility_section_present() {
    let report = minimal_report("10.0.0.1", "test");
    let output = format_human_report(&report);
    assert!(output.contains("Compatibility"));
    assert!(output.contains("Status:"));
    assert!(output.contains("Fidelity:"));
}

#[test]
fn format_status_uppercase_compatible() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Compatible;
    let output = format_human_report(&report);
    assert!(output.contains("COMPATIBLE"));
}

#[test]
fn format_status_uppercase_partial() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Partial;
    let output = format_human_report(&report);
    assert!(output.contains("PARTIAL"));
}

#[test]
fn format_status_uppercase_failed() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Failed;
    let output = format_human_report(&report);
    assert!(output.contains("FAILED"));
}

#[test]
fn format_status_uppercase_unsupported() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Unsupported;
    let output = format_human_report(&report);
    assert!(output.contains("UNSUPPORTED"));
}

#[test]
fn format_status_compatible_with_warnings() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::CompatibleWithWarnings;
    let output = format_human_report(&report);
    assert!(output.contains("COMPATIBLE (warnings)"));
}

#[test]
fn format_status_unknown() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Unknown;
    let output = format_human_report(&report);
    assert!(output.contains("UNKNOWN"));
}

#[test]
fn format_fidelity_approximate_prefix() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.fidelity = NseRunFidelity::Approximate;
    let output = format_human_report(&report);
    assert!(output.contains("~approximate"));
}

#[test]
fn format_fidelity_minimal_prefix() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.fidelity = NseRunFidelity::Minimal;
    let output = format_human_report(&report);
    assert!(output.contains("~minimal"));
}

#[test]
fn format_fidelity_full_no_prefix() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.fidelity = NseRunFidelity::Full;
    let output = format_human_report(&report);
    assert!(output.contains("  Fidelity: full"));
    assert!(!output.contains("~full"));
}

#[test]
fn format_capability_denials_visual_marker() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.capability_events = vec![NseCapabilityEventSummary {
        kind: "process_exec".to_string(),
        operation: "io.popen".to_string(),
        target: Some("ls".to_string()),
        allowed: false,
        reason: Some("denied by AgentSafe policy".to_string()),
    }];
    let output = format_human_report(&report);
    assert!(output.contains("Capability Denials"));
    assert!(output.contains("[!] process_exec on ls: denied by AgentSafe policy"));
}

#[test]
fn format_capability_denials_no_target() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.capability_events = vec![NseCapabilityEventSummary {
        kind: "filesystem_write".to_string(),
        operation: "io.open".to_string(),
        target: None,
        allowed: false,
        reason: None,
    }];
    let output = format_human_report(&report);
    assert!(output.contains("[!] filesystem_write: denied by policy"));
}

#[test]
fn format_warnings_visual_marker() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.warnings = vec!["test warning".to_string()];
    let output = format_human_report(&report);
    assert!(output.contains("[*] test warning"));
}

#[test]
fn format_libraries_warnings_visual_marker() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.libraries = vec![NseLibraryUseReport {
        name: "nmap".to_string(),
        category: "Core".to_string(),
        registered: true,
        side_effects: vec![],
        fallback_behavior: "HardFail".to_string(),
        notes: String::new(),
        loaded: true,
        warnings: vec!["some lib warning".to_string()],
    }];
    let output = format_human_report(&report);
    assert!(output.contains("[*] some lib warning"));
}

#[test]
fn format_rules_section() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: true,
        exactness: "exact".to_string(),
        error: None,
        summary: "rule matched".to_string(),
        unsupported: None,
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }];
    let output = format_human_report(&report);
    assert!(output.contains("Rule Evaluation"));
    assert!(output.contains("[portrule] matched (exact)"));
    assert!(output.contains("rule matched"));
}

#[test]
fn format_rules_with_unsupported() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.rules = vec![NseRuleEvaluationReport {
        kind: "hostrule".to_string(),
        evaluated: false,
        matched: false,
        exactness: "unsupported".to_string(),
        error: None,
        summary: "expected boolean, got string".to_string(),
        unsupported: Some("expected boolean, got string".to_string()),
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }];
    let output = format_human_report(&report);
    assert!(output.contains("unsupported: expected boolean, got string"));
}

#[test]
fn format_evidence_section() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.evidence = vec![NseEvidenceItem {
        id: "nse-ev-0".to_string(),
        kind: NseEvidenceKind::ServiceFingerprint,
        title: "OpenSSH detected".to_string(),
        summary: "SSH service found on port 22".to_string(),
        target: "10.0.0.1".to_string(),
        port: Some(22),
        service: Some("ssh".to_string()),
        confidence: "confirmed".to_string(),
        source: "ssl-cert".to_string(),
        raw_excerpt: None,
        references: vec![],
        tags: vec![],
    }];
    let output = format_human_report(&report);
    assert!(output.contains("Evidence (1 items)"));
    assert!(output.contains("[service-fingerprint] OpenSSH detected (confidence: confirmed)"));
    assert!(output.contains("SSH service found on port 22"));
}

#[test]
fn format_errors_section() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.errors = vec!["script execution failed".to_string()];
    let output = format_human_report(&report);
    assert!(output.contains("Errors"));
    assert!(output.contains("- script execution failed"));
}

#[test]
fn format_raw_output_truncation() {
    let mut report = minimal_report("10.0.0.1", "test");
    let lines: Vec<String> = (0..25).map(|i| format!("line {}", i)).collect();
    report.output = NseOutputSummary {
        has_output: true,
        content: lines.join("\n"),
        line_count: 25,
        truncated: false,
    };
    let output = format_human_report(&report);
    assert!(output.contains("Raw Output"));
    assert!(output.contains("line 0"));
    assert!(output.contains("line 19"));
    assert!(!output.contains("line 20"));
    assert!(output.contains("5 more lines"));
    assert!(output.contains("--json for full output"));
}

#[test]
fn format_raw_output_short() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.output = NseOutputSummary {
        has_output: true,
        content: "line 0\nline 1\nline 2".to_string(),
        line_count: 3,
        truncated: false,
    };
    let output = format_human_report(&report);
    assert!(output.contains("line 0"));
    assert!(output.contains("line 2"));
    assert!(!output.contains("more lines"));
}

#[test]
fn format_empty_output_no_raw_section() {
    let report = minimal_report("10.0.0.1", "test");
    let output = format_human_report(&report);
    assert!(!output.contains("Raw Output"));
}

#[test]
fn format_unsupported_features_shown() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.unsupported_features =
        vec!["nmap.socket".to_string(), "stdnse.sleep".to_string()];
    let output = format_human_report(&report);
    assert!(output.contains("Unsupported: nmap.socket, stdnse.sleep"));
}

#[test]
fn format_approximations_shown() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.approximations = vec!["portrule: synthetic host context".to_string()];
    let output = format_human_report(&report);
    assert!(output.contains("Approximations: portrule: synthetic host context"));
}

#[test]
fn format_libraries_section() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.libraries = vec![NseLibraryUseReport {
        name: "nmap".to_string(),
        category: "Core".to_string(),
        registered: true,
        side_effects: vec![],
        fallback_behavior: "HardFail".to_string(),
        notes: String::new(),
        loaded: true,
        warnings: vec![],
    }];
    let output = format_human_report(&report);
    assert!(output.contains("Libraries"));
    assert!(output.contains("nmap (Core, loaded)"));
}

#[test]
fn format_libraries_with_side_effects() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.libraries = vec![NseLibraryUseReport {
        name: "socket".to_string(),
        category: "Network".to_string(),
        registered: true,
        side_effects: vec![
            "network-access".to_string(),
            "process-execution".to_string(),
        ],
        fallback_behavior: "HardFail".to_string(),
        notes: String::new(),
        loaded: true,
        warnings: vec![],
    }];
    let output = format_human_report(&report);
    assert!(output.contains("[network-access, process-execution]"));
}

#[test]
fn format_json_path_works() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.compatibility.status = NseRunCompatibilityStatus::Partial;
    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(json.contains("10.0.0.1"));
    assert!(json.contains("ssl-cert") || json.contains("test"));
    assert!(json.contains("Partial"));
}

#[test]
fn format_deny_only_shows_non_allowed() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.capability_events = vec![
        NseCapabilityEventSummary {
            kind: "filesystem_read".to_string(),
            operation: "io.open".to_string(),
            target: Some("/etc/passwd".to_string()),
            allowed: true,
            reason: None,
        },
        NseCapabilityEventSummary {
            kind: "process_exec".to_string(),
            operation: "io.popen".to_string(),
            target: Some("id".to_string()),
            allowed: false,
            reason: Some("denied by policy".to_string()),
        },
    ];
    let output = format_human_report(&report);
    assert!(output.contains("Capability Denials"));
    assert!(output.contains("[!] process_exec"));
    assert!(!output.contains("[!] filesystem_read"));
}

#[test]
fn format_multiple_warnings() {
    let mut report = minimal_report("10.0.0.1", "test");
    report.warnings = vec!["warning one".to_string(), "warning two".to_string()];
    let output = format_human_report(&report);
    assert!(output.contains("[*] warning one"));
    assert!(output.contains("[*] warning two"));
}
