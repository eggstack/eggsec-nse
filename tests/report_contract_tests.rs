//! Milestone 001 Work Package A — report and behavior baselines.
//!
//! Regression evidence captured BEFORE canonical orchestration convergence.
//! These tests freeze:
//! 1. The serialized `NseRunReport` field contract (no section may be
//!    silently dropped by the later consolidation).
//! 2. Representative report states: matched rule, unmatched rule,
//!    compatibility downgrade/diagnostic, capability denial.
//! 3. Current profile defaults for runtime CLI / manual Eggsec / Python
//!    surfaces (manual-permissive vs agent-safe script-file policy).

#![cfg(feature = "nse")]

use eggsec_nse::profile::ResolvedNseExecutionProfile;
use eggsec_nse::report::*;
use eggsec_nse::resolver::{NseLoadDiagnostic, NseScriptSource};

fn representative_profile() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"))
}

fn matched_rule() -> NseRuleEvaluationReport {
    NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: true,
        exactness: "exact".to_string(),
        error: None,
        summary: "rule matched".to_string(),
        unsupported: None,
        host_context_source: Some("synthetic".to_string()),
        port_context_source: Some("synthetic".to_string()),
        service_context_available: Some(false),
        fidelity_reason: None,
    }
}

fn unmatched_rule() -> NseRuleEvaluationReport {
    NseRuleEvaluationReport {
        kind: "hostrule".to_string(),
        evaluated: true,
        matched: false,
        exactness: "exact".to_string(),
        error: None,
        summary: "rule did not match".to_string(),
        unsupported: None,
        host_context_source: Some("synthetic".to_string()),
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }
}

fn build_representative_report() -> NseRunReport {
    let profile = representative_profile();
    let source = NseScriptSource::Builtin {
        name: "banner".to_string(),
    };
    let diagnostics = vec![NseLoadDiagnostic::Resolved {
        source: source.clone(),
        bytes: 128,
    }];
    NseRunReport::new("127.0.0.1", "banner")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_rules(vec![matched_rule(), unmatched_rule()])
        .with_libraries(vec![])
        .with_capability_events(vec![])
        .with_output("banner: test-service")
        .compute_compatibility()
}

#[test]
fn report_serialized_contract_has_all_sections() {
    let report = build_representative_report();
    let value = serde_json::to_value(&report).expect("report must serialize");

    for section in [
        "target",
        "script_name",
        "script_source",
        "profile",
        "sandbox",
        "limits",
        "stats",
        "resolver",
        "libraries",
        "rules",
        "output",
        "compatibility",
        "capability_events",
        "evidence",
        "warnings",
        "errors",
    ] {
        assert!(
            value.get(section).is_some(),
            "serialized NseRunReport must contain section '{}'",
            section
        );
    }

    // Failing this test means a report section was silently dropped.
    assert_eq!(value["target"], "127.0.0.1");
    assert_eq!(value["script_name"], "banner");
    assert_eq!(value["rules"].as_array().unwrap().len(), 2);
    assert_eq!(value["resolver"]["total_diagnostics"], 1);
    assert!(value["output"]["has_output"].as_bool().unwrap());
}

#[test]
fn report_contract_matched_and_unmatched_rules() {
    let report = build_representative_report();
    assert!(report.rules.iter().any(|r| r.matched));
    assert!(report.rules.iter().any(|r| r.evaluated && !r.matched));

    let value = serde_json::to_value(&report).expect("report must serialize");
    let kinds: Vec<&str> = value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"portrule"));
    assert!(kinds.contains(&"hostrule"));
}

#[test]
fn report_contract_compatibility_downgrade_case() {
    // Approximate rule exactness must downgrade compatibility/fidelity.
    let profile = representative_profile();
    let source = NseScriptSource::Builtin {
        name: "banner".to_string(),
    };
    let mut approx = matched_rule();
    approx.exactness = "approximate".to_string();
    let report = NseRunReport::new("127.0.0.1", "banner")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&[])
        .with_rules(vec![approx])
        .with_output("out")
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Approximate);
    assert_eq!(report.compatibility.approximations.len(), 1);
}

#[test]
fn report_contract_capability_denial_case() {
    use eggsec_nse::capabilities::{NseCapabilityEvent, NseCapabilityKind};
    let profile = representative_profile();
    let source = NseScriptSource::Builtin {
        name: "banner".to_string(),
    };
    let event = NseCapabilityEvent {
        kind: NseCapabilityKind::ProcessExec,
        operation: "io.popen".to_string(),
        target: Some("true".to_string()),
        allowed: false,
        reason: Some("denied by profile".to_string()),
        bytes: None,
    };
    let report = NseRunReport::new("127.0.0.1", "banner")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&[])
        .with_capability_events(vec![event])
        .with_output("")
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial,
        "capability denial must surface as Partial compatibility"
    );

    let evidence = extract_evidence(
        &report.target,
        &report.script_name,
        &report.capability_events,
        &report.compatibility,
        &report.rules,
        &report.output,
    );
    assert!(
        evidence
            .iter()
            .any(|e| matches!(e.kind, NseEvidenceKind::CapabilityDenial)),
        "capability denial must produce CapabilityDenial evidence"
    );
}

#[test]
fn profile_defaults_manual_permits_script_files() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    assert!(
        profile.script_policy.allow_script_files,
        "runtime CLI / manual Eggsec default must permit script files"
    );
    assert_eq!(
        profile.kind,
        eggsec_nse::NseExecutionProfileKind::ManualPermissive
    );
}

#[test]
fn profile_defaults_agent_safe_denies_script_files() {
    // Python binding default: automated surface must not accept script files.
    let profile = ResolvedNseExecutionProfile::agent_safe("127.0.0.1", &[]);
    assert!(
        !profile.script_policy.allow_script_files,
        "Python AgentSafe default must deny script files"
    );
    assert_eq!(profile.kind, eggsec_nse::NseExecutionProfileKind::AgentSafe);
}

#[test]
fn failure_report_contract_carries_error_and_profile() {
    let profile = representative_profile();
    let source = NseScriptSource::File {
        path: std::path::PathBuf::from("/tmp/blocked.nse"),
    };
    let report = NseRunReport::new("127.0.0.1", "blocked")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_error("Profile 'agent-safe' does not allow arbitrary script files.")
        .compute_compatibility();

    assert_eq!(report.errors.len(), 1);
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
    assert_eq!(report.profile.kind, "manual-permissive");
    assert_eq!(report.script_source.kind, "file");
}
