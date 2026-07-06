//! End-to-end verification of NSE profile/report capability events.
//!
//! These tests verify that capability events flow correctly through the
//! capability context and appear in `NseRunReport.capability_events` via
//! `with_capability_events()`. They exercise the profile→context→event→report
//! pipeline for each automated profile.
//!
//! See Milestone 3 closure verification pass.

#![cfg(feature = "nse")]

use eggsec_nse::capabilities::{NseCapabilityKind, NseCapabilityRequest};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
};
use eggsec_nse::report::{NseRunCompatibilityStatus, NseRunReport};
use eggsec_nse::{
    NseCancellationToken, NseCapabilityContext, NseExecutionLimits, NseResourceCounters,
    SandboxConfig,
};
use std::sync::Arc;

fn make_ctx(profile: NseExecutionProfileKind) -> NseCapabilityContext {
    let counters = Arc::new(NseResourceCounters::new());
    NseCapabilityContext::new(
        profile,
        NseNetworkPolicy::AllowAllManual,
        NseScriptPolicy {
            allow_builtin_scripts: true,
            allow_script_files: true,
            allowed_script_roots: vec![],
            allow_conventional_nmap_paths: false,
            max_script_bytes: Some(5_000_000),
        },
        NseModulePolicy {
            allow_builtin_modules: true,
            allow_filesystem_modules: true,
            allowed_module_roots: vec![],
            max_module_bytes: Some(2_000_000),
        },
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        counters,
    )
}

// ---------------------------------------------------------------------------
// 1. AgentSafe process exec denied — event flows into report
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_process_exec_denied_in_report() {
    let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "process_exec",
    });
    assert!(decision.is_denied(), "AgentSafe must deny process exec");

    let events = ctx.events();
    assert!(!events.is_empty(), "events must not be empty after check");

    let report = NseRunReport::new("test-host", "test-script")
        .with_capability_events(events)
        .compute_compatibility();

    assert!(
        !report.capability_events.is_empty(),
        "report must carry capability events"
    );

    let ev = &report.capability_events[0];
    assert_eq!(ev.kind, "process_exec");
    assert_eq!(ev.operation, "process_exec");
    assert!(!ev.allowed, "process_exec must be denied under AgentSafe");

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial,
        "capability denials must produce Partial compatibility"
    );
}

// ---------------------------------------------------------------------------
// 2. AgentSafe unscoped filesystem read denied — event flows into report
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_unscoped_fs_read_denied_in_report() {
    let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemRead,
        target: Some("/etc/passwd".to_string()),
        bytes_hint: None,
        operation: "filesystem_read",
    });
    assert!(
        decision.is_denied(),
        "AgentSafe must deny unscoped filesystem read"
    );

    let events = ctx.events();
    let report = NseRunReport::new("test-host", "test-script").with_capability_events(events);

    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "filesystem_read" && !e.allowed),
        "report must contain a denied filesystem_read event"
    );
}

// ---------------------------------------------------------------------------
// 3. AgentSafe scoped filesystem read allowed — event flows into report
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_scoped_fs_read_allowed_in_report() {
    let mut ctx = make_ctx(NseExecutionProfileKind::AgentSafe);

    let dir = std::env::temp_dir().join("eggsec_nse_profile_report_test");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("scoped.txt");
    std::fs::write(&path, b"scoped content").expect("write test file");

    ctx.sandbox.enabled = true;
    ctx.sandbox.allowed_dir = Some(dir.clone());

    let target = path.to_string_lossy().to_string();
    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemRead,
        target: Some(target),
        bytes_hint: None,
        operation: "filesystem_read",
    });
    assert!(
        decision.is_allowed(),
        "AgentSafe must allow scoped filesystem read, got {:?}",
        decision
    );

    let events = ctx.events();
    let report = NseRunReport::new("test-host", "test-script").with_capability_events(events);

    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "filesystem_read" && e.allowed),
        "report must contain an allowed filesystem_read event"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

// ---------------------------------------------------------------------------
// 4. CiSafe network TCP and DNS denied — events flow into report
// ---------------------------------------------------------------------------

#[test]
fn ci_safe_network_dns_denied_in_report() {
    let ctx = make_ctx(NseExecutionProfileKind::CiSafe);

    let tcp_decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::NetworkTcp,
        target: Some("10.0.0.1".to_string()),
        bytes_hint: None,
        operation: "network_tcp",
    });
    assert!(tcp_decision.is_denied(), "CiSafe must deny NetworkTcp");

    let dns_decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::DnsResolution,
        target: Some("example.com".to_string()),
        bytes_hint: None,
        operation: "dns_resolution",
    });
    assert!(dns_decision.is_denied(), "CiSafe must deny DnsResolution");

    let events = ctx.events();
    let report = NseRunReport::new("test-host", "test-script")
        .with_capability_events(events)
        .compute_compatibility();

    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "network_tcp" && !e.allowed),
        "report must contain a denied network_tcp event"
    );
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "dns_resolution" && !e.allowed),
        "report must contain a denied dns_resolution event"
    );

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial,
        "capability denials must produce Partial compatibility"
    );
}

// ---------------------------------------------------------------------------
// 5. ManualPermissive process exec warning — event flows into report
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_process_exec_warning_in_report() {
    let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "process_exec",
    });
    assert!(
        decision.is_allowed(),
        "ManualPermissive must allow process exec"
    );
    assert!(
        decision.warning().is_some(),
        "ManualPermissive must warn on process exec"
    );

    let events = ctx.events();
    let report = NseRunReport::new("test-host", "test-script").with_capability_events(events);

    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "process_exec" && e.allowed),
        "report must contain an allowed process_exec event"
    );

    let ev = report
        .capability_events
        .iter()
        .find(|e| e.kind == "process_exec")
        .expect("process_exec event must exist");
    assert!(
        ev.reason
            .as_ref()
            .map_or(false, |r| r.contains("manual permissive")),
        "warning reason must mention manual permissive mode, got {:?}",
        ev.reason
    );
}
