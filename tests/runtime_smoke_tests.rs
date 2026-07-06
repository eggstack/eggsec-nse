//! End-to-end smoke tests for the NSE runtime execution pipeline.
//!
//! These tests exercise the runtime path:
//! 1. Build a `ResolvedNseExecutionProfile` (canonical surface-construction).
//! 2. Construct `NseExecutor::with_profile(&profile)`.
//! 3. Inject target/ports via `set_target` / `add_port`.
//! 4. Resolve and execute the script via `run_script_with_rules`.
//! 5. Build an `NseRunReport` via the builder chain.
//! 6. Bridge to `ReportEnvelope` and assert envelope shape.
//!
//! The goal is to verify the full pipeline (profile → context → execution →
//! report → envelope) produces a consistent, well-formed envelope for
//! representative NSE scenarios. This complements the runtime_corpus_tests
//! manifest-driven tests and the unit-level profile_report_tests.

#![cfg(feature = "nse")]

use eggsec_nse::bridge::to_report_envelope;
use eggsec_nse::executor::NseExecutor;
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    ResolvedNseExecutionProfile,
};
use eggsec_nse::report::{NseRunCompatibilityStatus, NseRunFidelity, NseRunReport};
use eggsec_nse::{NseEvidenceItem, NseEvidenceKind, SandboxConfig};

fn make_profile(kind: NseExecutionProfileKind, allow_files: bool) -> ResolvedNseExecutionProfile {
    let script_policy = NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: allow_files,
        allowed_script_roots: vec![],
        allow_conventional_nmap_paths: false,
        max_script_bytes: Some(5_000_000),
    };
    let module_policy = NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: allow_files,
        allowed_module_roots: vec![],
        max_module_bytes: Some(2_000_000),
    };
    let network_policy = match kind {
        NseExecutionProfileKind::CiSafe | NseExecutionProfileKind::AgentSafe => {
            NseNetworkPolicy::DenyAll
        }
        _ => NseNetworkPolicy::AllowAllManual,
    };
    ResolvedNseExecutionProfile {
        kind,
        sandbox: SandboxConfig::default(),
        limits: eggsec_nse::NseExecutionLimits::default(),
        script_policy,
        module_policy,
        network_policy,
        audit_label: "nse:smoke-test".to_string(),
        warnings: vec![],
    }
}

fn build_envelope_from_execution(
    profile: &ResolvedNseExecutionProfile,
    script: &str,
    target: &str,
    port: u16,
) -> (NseRunReport, Vec<NseEvidenceItem>) {
    let mut executor = NseExecutor::with_profile(profile).expect("executor construction");
    executor.set_target(target).expect("set_target");
    executor
        .add_port(port, "tcp", "open", None)
        .expect("add_port");

    let source = eggsec_nse::resolver::NseScriptSource::InlineManual {
        label: "smoke".to_string(),
        content: script.to_string(),
    };
    let mut resolver = eggsec_nse::resolver::ScriptResolver::new(
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.limits.clone(),
    );
    let resolved = resolver.resolve_script(source).expect("resolve_script");

    let (output, _raw, rule_reports) = executor
        .run_script_with_rules(&resolved.content)
        .expect("run_script_with_rules");

    let library_reports = executor.library_reports();
    let capability_events = executor.capability_events();

    let mut report = NseRunReport::new(target, "smoke")
        .with_profile(profile)
        .with_script_source(&resolved.source)
        .with_stats(&executor.execution_stats())
        .with_resolver_diagnostics(&resolver.take_diagnostics())
        .with_rules(rule_reports.clone())
        .with_libraries(library_reports)
        .with_capability_events(capability_events.clone())
        .with_output(&output)
        .compute_compatibility();

    let evidence = eggsec_nse::report::extract_evidence(
        &report.target,
        &report.script_name,
        &report.capability_events,
        &report.compatibility,
        &report.rules,
        &report.output,
    );
    report = report.with_evidence(evidence.clone());

    (report, evidence)
}

#[test]
fn smoke_compatibility_lab_executes_and_emits_compatible_envelope() {
    let profile = make_profile(NseExecutionProfileKind::CompatibilityLab, true);
    let script = r#"
description = [[Smoke: simple portrule that matches our injected port.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  return "smoke-ok"
end
"#;
    let (report, _evidence) = build_envelope_from_execution(&profile, script, "127.0.0.1", 80);

    assert!(
        matches!(
            report.compatibility.status,
            NseRunCompatibilityStatus::Compatible
                | NseRunCompatibilityStatus::CompatibleWithWarnings
        ),
        "smoke fixture should be Compatible or CompatibleWithWarnings under CompatibilityLab; got {:?}",
        report.compatibility.status,
    );
    // Fidelity may be Approximate because the harness injects a synthetic host/port
    // context, which the rule evaluator downgrades to approximate. This is by design.
    assert!(matches!(
        report.compatibility.fidelity,
        NseRunFidelity::Full | NseRunFidelity::Approximate
    ));
    assert!(!report.output.content.is_empty());

    let envelope = to_report_envelope(&report);
    assert_eq!(envelope.domain_id.as_deref(), Some("nse"));
    assert!(
        envelope.findings.iter().any(|f| f.id == "metadata-nse"),
        "envelope must include execution metadata finding",
    );
    assert!(
        envelope
            .findings
            .iter()
            .all(|f| f.severity == eggsec_core::types::Severity::Info),
        "compatible smoke envelope should have only Info findings",
    );
}

#[test]
fn smoke_agent_safe_executes_and_capability_denials_surface_in_envelope() {
    let profile = make_profile(NseExecutionProfileKind::AgentSafe, true);
    let script = r#"
description = [[Smoke: process exec under AgentSafe is denied.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  local f = io.popen("true", "r")
  if f then f:close() end
  return "tried process exec"
end
"#;
    let (report, evidence) = build_envelope_from_execution(&profile, script, "127.0.0.1", 80);

    // Status is Partial because capability denials are observed.
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Partial,
        "AgentSafe process exec should produce Partial status; got {:?}",
        report.compatibility.status,
    );

    let envelope = to_report_envelope(&report);
    assert_eq!(envelope.domain_id.as_deref(), Some("nse"));

    // Either the report records a process_exec capability denial, or the
    // evidence list contains a CapabilityDenial item — either signals the
    // envelope carried the runtime instrumentation.
    let saw_denial_in_evidence = evidence
        .iter()
        .any(|e| matches!(e.kind, NseEvidenceKind::CapabilityDenial));
    let saw_denial_in_events = report
        .capability_events
        .iter()
        .any(|e| !e.allowed && e.kind.contains("process_exec"));

    assert!(
        saw_denial_in_evidence || saw_denial_in_events,
        "expected a process_exec capability denial in evidence or events; events={:?}, evidence={:?}",
        report.capability_events,
        evidence.iter().map(|e| (&e.kind, &e.title)).collect::<Vec<_>>(),
    );
}
